-module(srpc_srv).

-author("paul@knoxen.com").

%%================================================================================================
%%
%% API exports
%%
%%================================================================================================
-export([lib_key_exchange/1
        ,lib_key_validate/2
        ,user_registration/2
        ,user_key_exchange/2
        ,user_key_validate/2
        ,server_epoch/2
        ,encrypt_data/2
        ,decrypt_data/2
        ,client_map_for_id/1
        ,invalidate/2
        ]).

-define(APP_NAME, srpc_srv).

-define(DATA_HDR_VSN,   1).
-define(DATA_HDR_BITS,  8).
-define(EPOCH_BITS,    32).

%%================================================================================================
%%
%% Registration Codes
%%
%%================================================================================================
-define(SRPC_REGISTRATION_CREATE,      1).
-define(SRPC_REGISTRATION_UPDATE,      2).
-define(SRPC_REGISTRATION_OK,         10).
-define(SRPC_REGISTRATION_DUP,        11).
-define(SRPC_REGISTRATION_NOT_FOUND,  12).
-define(SRPC_REGISTRATION_ERROR,     255).

%%================================================================================================
%%
%% Lib Client Key Agreement
%%
%%================================================================================================
%%------------------------------------------------------------------------------------------------
%%
%%   Lib Key Exchange
%%
%%------------------------------------------------------------------------------------------------
lib_key_exchange(ExchangeRequest) ->
  case srpc_lib:lib_key_process_exchange_request(ExchangeRequest) of
    {ok, {ClientPublicKey, ReqExchangeData}} ->
      RespExchangeData = srpc_app_hook:lib_key_exchange_data(ReqExchangeData),
      case srpc_lib:lib_key_create_exchange_response(ClientPublicKey, RespExchangeData) of
        {ok, {ExchangeMap, ExchangeResponse}} ->
          ClientId = maps:get(clientId, ExchangeMap),
          srpc_app_hook:put(ClientId, ExchangeMap, srpc_exchanges),
          {ok, ExchangeResponse};
        Error ->
          Error
      end;
    Error ->
      Error
  end.

%%------------------------------------------------------------------------------------------------
%%
%%   Lib Key Validate
%%
%%------------------------------------------------------------------------------------------------
lib_key_validate(ClientId, ValidationRequest) ->
  case srpc_app_hook:get(ClientId, srpc_exchanges) of
    {ok, ExchangeMap} ->
      srpc_app_hook:delete(ClientId, srpc_exchanges),
      case srpc_lib:lib_key_process_validation_request(ExchangeMap, ValidationRequest) of
        {ok, {_ReqClientId, ClientChallenge, ReqValidationData}} ->
          RespValidationData = srpc_app_hook:lib_key_validation_data(ReqValidationData),
          case srpc_lib:lib_key_create_validation_response(ExchangeMap, ClientChallenge,
                                                           RespValidationData) of
            {ok, ClientMap, ValidationResponse} ->
              srpc_app_hook:put(ClientId, ClientMap, srpc_lib_clients),
              {ok, ValidationResponse};
            {invalid, _ClientMap, ValidationResponse} ->
              {ok, ValidationResponse};
            Error ->
              Error
          end;
        Error ->
          Error
      end;
    undefined ->
      {error, <<"No exchange info for Client Id: ", ClientId/binary>>}
  end.

%%================================================================================================
%%
%% User Registration
%%
%%================================================================================================
user_registration(ClientId, RegistrationRequest) ->
  case client_map_for_id(ClientId) of
    {ok, ClientMap} ->
      case srpc_lib:process_registration_request(ClientMap, RegistrationRequest) of
        {ok, {RegistrationCode, SrpcUserData, SrpcReqData}} ->
          UserId = maps:get(userId, SrpcUserData),
          case parse_req_data(SrpcReqData) of
            {ok, ReqRegistrationData} ->
              RespRegistrationData = srpc_app_hook:registration_data(UserId, ReqRegistrationData),
              SrpcRespData = create_resp_data(<<>>, RespRegistrationData),
              case RegistrationCode of
                ?SRPC_REGISTRATION_CREATE ->
                  case srpc_app_hook:get(UserId, srpc_users) of
                    undefined ->
                      srpc_app_hook:put(UserId, SrpcUserData, srpc_users),
                      srpc_lib:create_registration_response(ClientMap,
                                                            ?SRPC_REGISTRATION_OK,
                                                            SrpcRespData);
                    {ok, _SrpcUserData} ->
                      srpc_lib:create_registration_response(ClientMap,
                                                            ?SRPC_REGISTRATION_DUP,
                                                            SrpcRespData)
                  end;
                ?SRPC_REGISTRATION_UPDATE ->
                  case srpc_app_hook:get(UserId, srpc_users) of
                    {ok, _SrpcUserData} ->
                      srpc_app_hook:put(UserId, SrpcUserData, srpc_users),
                      srpc_lib:create_registration_response(ClientMap,
                                                            ?SRPC_REGISTRATION_OK,
                                                            SrpcRespData);
                    undefined ->
                      srpc_lib:create_registration_response(ClientMap,
                                                            ?SRPC_REGISTRATION_NOT_FOUND,
                                                            SrpcRespData)
                  end;
                _ ->
                  srpc_lib:create_registration_response(ClientMap,
                                                        ?SRPC_REGISTRATION_ERROR,
                                                        SrpcRespData)
              end;
            Error ->
              Error
          end;
        Error ->
          Error
      end;
    Error ->
      Error
  end.

%%================================================================================================
%%
%% User Client Key Agreement
%%
%%================================================================================================
%%------------------------------------------------------------------------------------------------
%%
%%   User Key Exchange
%%
%%------------------------------------------------------------------------------------------------
user_key_exchange(CryptClientId, ExchangeRequest) ->
  case client_map_for_id(CryptClientId) of
    {ok, CryptClientMap} ->
      case srpc_lib:user_key_process_exchange_request(CryptClientMap, ExchangeRequest) of
        {ok, {UserId, ClientPublicKey, SrpcReqData}} ->
          case parse_req_data(SrpcReqData) of
            {ok, ReqExchangeData} ->
              case srpc_app_hook:get(UserId, srpc_users) of
                {ok, SrpcUserData} ->
                  RespExchangeData = srpc_app_hook:user_key_exchange_data(UserId, ReqExchangeData),

                  SrpcData = <<>>,
                  SrpcRespData = create_resp_data(SrpcData, RespExchangeData),
                  case srpc_lib:user_key_create_exchange_response(CryptClientMap,
                                                                  SrpcUserData,
                                                                  ClientPublicKey, 
                                                                  SrpcRespData) of
                    {ok, {ExchangeMap, ExchangeResponse}} ->
                      ExchangeClientId = maps:get(clientId, ExchangeMap),
                      srpc_app_hook:put(ExchangeClientId, ExchangeMap, srpc_exchanges),
                      {ok, ExchangeResponse};
                    Error ->
                      Error
                  end;
                undefined ->
                  srpc_lib:user_key_create_exchange_response(CryptClientMap, invalid, 
                                                             ClientPublicKey, UserId)
              end;
            Error ->
              Error
          end;
        Error ->
          Error
      end;
    Error ->
      Error
  end.

%%------------------------------------------------------------------------------------------------
%%
%%   User Key Validation
%%
%%------------------------------------------------------------------------------------------------
user_key_validate(CryptClientId, ValidationRequest) ->
  case client_map_for_id(CryptClientId) of
    {ok, CryptClientMap} ->
      case srpc_lib:user_key_process_validation_request(CryptClientMap, ValidationRequest) of
        {ok, {UserClientId, ClientChallenge, SrpcReqValidationData}} ->
          case srpc_app_hook:get(UserClientId, srpc_exchanges) of
            {ok, ExchangeMap} ->
              srpc_app_hook:delete(UserClientId, srpc_exchanges),
              case parse_req_data(SrpcReqValidationData) of
                {ok, ReqValidationData} ->
                  UserId = maps:get(entityId, ExchangeMap),
                  RespValidationData = 
                    srpc_app_hook:user_key_validation_data(UserId, ReqValidationData),
                  SrpcRespData = create_resp_data(<<>>, RespValidationData),
                  case srpc_lib:user_key_create_validation_response(CryptClientMap, ExchangeMap,
                                                                    ClientChallenge,
                                                                    SrpcRespData) of
                    {ok, ClientMap, ValidationResponse} ->
                      srpc_app_hook:put(UserClientId, 
                                        maps:put(clientId, UserClientId, ClientMap),
                                        srpc_user_clients),
                      {ok, ValidationResponse};
                    {invalid, _ClientMap, ValidationResponse} ->
                      %% CxTBD Report invalid
                      {ok, ValidationResponse}
                  end;
                Error ->
                  Error
              end;
            undefined ->
              SrpcRespData = create_resp_data(<<>>, <<>>),
              {_, _ClientMap, ValidationResponse} =
                srpc_lib:user_key_create_validation_response(CryptClientMap, invalid,
                                                             ClientChallenge, SrpcRespData),
              {ok, ValidationResponse}
          end
      end;
    Error ->
      Error
  end.

%%================================================================================================
%%
%% Client Invalidate
%%
%%================================================================================================
invalidate(ClientId, InvalidateRequest) ->
  case client_map_for_id(ClientId) of
    {ok, ClientMap} ->
      case srpc_encryptor:decrypt(ClientMap, InvalidateRequest) of
        {ok, ClientId} ->
          ClientType = maps:get(clientType, ClientMap),
          Cache = erlang:list_to_atom(erlang:atom_to_list(ClientType) ++ "s"),
          srpc_app_hook:delete(ClientId, Cache),
          encrypt_data(ClientMap, ClientId);
        {ok, _ClientId} ->
          {error, <<"Invalid encrypted Client ID">>};
        Error ->
          Error
      end;
    Error ->
      Error
  end.

%%================================================================================================
%%
%% Server Epoch
%%
%%================================================================================================
server_epoch(ClientId, ServerEpochRequest) ->
  case client_map_for_id(ClientId) of
    {ok, ClientMap} ->
      case srpc_encryptor:decrypt(ClientMap, ServerEpochRequest) of
        {ok, <<RandomStamp/binary>>} ->
          DataEpoch = erlang:system_time(seconds),
          RespData = <<DataEpoch:?EPOCH_BITS, RandomStamp/binary>>,
          srpc_encryptor:encrypt(ClientMap, RespData);
        {ok, _ReqData} ->
          {error, <<"Invalid data epoch stamp">>};
        Error ->
          Error
      end;
    Error ->
      Error
  end.    

%%================================================================================================
%%
%% Key Map
%%
%%================================================================================================
%%------------------------------------------------------------------------------------------------
%%
%%
%%
%%------------------------------------------------------------------------------------------------
client_map_for_id(ClientId) ->
  case srpc_app_hook:get(ClientId, srpc_lib_clients) of
    undefined ->
      case srpc_app_hook:get(ClientId, srpc_user_clients) of
        undefined ->
          case srpc_app_hook:get(ClientId, srpc_exchanges) of
            undefined ->
              {error, <<"No Key Map for ClientId: ", ClientId/binary>>};
            Result ->
              Result
          end;
        Result ->
          Result
      end;
    Result ->
      Result
  end.

%%================================================================================================
%%
%% Encrypt / Decrypt
%%
%%================================================================================================
encrypt_data(ClientMap, Data) ->
  SrpcData = create_resp_data(<<>>, Data),
  srpc_lib:encrypt(ClientMap, SrpcData).

decrypt_data(ClientMap, Data) ->
  case srpc_lib:decrypt(ClientMap, Data) of
    {ok, SrpcData} ->
      parse_req_data(SrpcData);
    Error ->
      Error
  end.

%%================================================================================================
%%
%% Private functions
%%
%%================================================================================================
%%------------------------------------------------------------------------------------------------
%%
%%
%%
%%------------------------------------------------------------------------------------------------
req_age_tolerance() ->
  case application:get_env(req_age_tolerance) of
    {ok, AgeTolerance} ->
      AgeTolerance;
    undefined ->
      {ok, AgeTolerance} = application:get_env(?APP_NAME, req_age_tolerance),
      AgeTolerance
  end.

%%------------------------------------------------------------------------------------------------
%%
%%
%%
%%------------------------------------------------------------------------------------------------
parse_req_data(<<?DATA_HDR_VSN:?DATA_HDR_BITS, DataEpoch:?EPOCH_BITS, ReqData/binary>>) ->
  Tolerance = req_age_tolerance(),
  ReqEpoch = erlang:system_time(seconds),
  case abs(ReqEpoch - DataEpoch) =< Tolerance of
    true ->
      {ok, ReqData};
    false ->
      {error, <<"Request data age is greater than tolerance">>}
  end;
parse_req_data(<<_:?DATA_HDR_BITS, _Rest/binary>>) ->
  {error, <<"Invalid Srpc data version number">>};
parse_req_data(_SrpcReqData) ->
  {error, <<"Invalid Srpc request data">>}.

%%------------------------------------------------------------------------------------------------
%%
%%
%%
%%------------------------------------------------------------------------------------------------
create_resp_data(SrpcData, RespData) ->
  ServerEpoch = erlang:system_time(seconds),
  << ?DATA_HDR_VSN:?DATA_HDR_BITS, ServerEpoch:?EPOCH_BITS, SrpcData/binary, RespData/binary >>.
