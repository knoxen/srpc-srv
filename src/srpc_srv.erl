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
        ,key_map_for_key_id/1
        ,key_invalidate/2
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
%% Lib Key Agreement
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
          KeyId = maps:get(keyId, ExchangeMap),
          srpc_app_hook:put(exchange_info, KeyId, ExchangeMap),
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
lib_key_validate(KeyId, ValidationRequest) ->
  case srpc_app_hook:get(exchange_info, KeyId) of
    {ok, ExchangeMap} ->
      case srpc_lib:lib_key_process_validation_request(ExchangeMap, ValidationRequest) of
        {ok, {_ReqKeyId, ClientChallenge, ReqValidationData}} ->
          RespValidationData = srpc_app_hook:lib_key_validation_data(ReqValidationData),
          case srpc_lib:lib_key_create_validation_response(ExchangeMap, ClientChallenge,
                                                           RespValidationData) of
            {ok, KeyMap, ValidationResponse} ->
              srpc_app_hook:put(lib_key, KeyId, KeyMap),
              {ok, ValidationResponse};
            {invalid, _KeyMap, ValidationResponse} ->
              {ok, ValidationResponse};
            Error ->
              Error
          end;
        Error ->
          Error
      end;
    undefined ->
      {error, <<"No exchange info for keyId: ", KeyId/binary>>}
  end.

%%================================================================================================
%%
%% User Registration
%%
%%================================================================================================
user_registration(KeyId, RegistrationRequest) ->
  case key_map_for_key_id(KeyId) of
    {ok, KeyMap} ->
      case srpc_lib:process_registration_request(KeyMap, RegistrationRequest) of
        {ok, {RegistrationCode, SrpcUserData, SrpcHttpReqData}} ->
          UserId = maps:get(userId, SrpcUserData),
          case parse_req_data(SrpcHttpReqData) of
            {ok, ReqRegistrationData} ->
              RespRegistrationData = srpc_app_hook:registration_data(UserId, ReqRegistrationData),
              SrpcHttpRespData = create_resp_data(<<>>, RespRegistrationData),
              case RegistrationCode of
                ?SRPC_REGISTRATION_CREATE ->
                  case srpc_app_hook:get(srpc_user, UserId) of
                    undefined ->
                      srpc_app_hook:put(srpc_user, UserId, SrpcUserData),
                      srpc_lib:create_registration_response(KeyMap,
                                                            ?SRPC_REGISTRATION_OK,
                                                            SrpcHttpRespData);
                    {ok, _SrpcUserData} ->
                      srpc_lib:create_registration_response(KeyMap,
                                                            ?SRPC_REGISTRATION_DUP,
                                                            SrpcHttpRespData)
                  end;
                ?SRPC_REGISTRATION_UPDATE ->
                  case srpc_app_hook:get(srpc_user, UserId) of
                    {ok, _SrpcUserData} ->
                      srpc_app_hook:put(srpc_user, UserId, SrpcUserData),
                      srpc_lib:create_registration_response(KeyMap,
                                                            ?SRPC_REGISTRATION_OK,
                                                            SrpcHttpRespData);
                    undefined ->
                      srpc_lib:create_registration_response(KeyMap,
                                                            ?SRPC_REGISTRATION_NOT_FOUND,
                                                            SrpcHttpRespData)
                  end;
                _ ->
                  srpc_lib:create_registration_response(KeyMap,
                                                        ?SRPC_REGISTRATION_ERROR,
                                                        SrpcHttpRespData)
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
%% User Key Agreement
%%
%%================================================================================================
%%------------------------------------------------------------------------------------------------
%%
%% User Key Exchange
%%
%%------------------------------------------------------------------------------------------------
user_key_exchange(CryptKeyId, ExchangeRequest) ->
  case key_map_for_key_id(CryptKeyId) of
    {ok, CryptKeyMap} ->
      case srpc_lib:user_key_process_exchange_request(CryptKeyMap, ExchangeRequest) of
        {ok, {UserId, ClientPublicKey, SrpcHttpReqData}} ->
          case parse_req_data(SrpcHttpReqData) of
            {ok, ReqExchangeData} ->
              case srpc_app_hook:get(srpc_user, UserId) of
                {ok, SrpcUserData} ->
                  RespExchangeData = srpc_app_hook:user_key_exchange_data(UserId, ReqExchangeData),

                  SrpcHttpData = <<>>,
                  SrpcHttpRespData = create_resp_data(SrpcHttpData, RespExchangeData),
                  case srpc_lib:user_key_create_exchange_response(CryptKeyMap,
                                                                  SrpcUserData,
                                                                  ClientPublicKey, 
                                                                  SrpcHttpRespData) of
                    {ok, {ExchangeMap, ExchangeResponse}} ->
                      ExchangeKeyId = maps:get(keyId, ExchangeMap),
                      srpc_app_hook:put(exchange_info, ExchangeKeyId, ExchangeMap),
                      {ok, ExchangeResponse};
                    Error ->
                      Error
                  end;
                undefined ->
                  srpc_lib:user_key_create_exchange_response(CryptKeyMap, invalid, 
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
%% User Key Validation
%%
%%------------------------------------------------------------------------------------------------
user_key_validate(CryptKeyId, ValidationRequest) ->
  case key_map_for_key_id(CryptKeyId) of
    {ok, CryptKeyMap} ->
      case srpc_lib:user_key_process_validation_request(CryptKeyMap, ValidationRequest) of
        {ok, {UserKeyId, ClientChallenge, SrpcHttpReqValidationData}} ->
          case srpc_app_hook:get(exchange_info, UserKeyId) of
            {ok, ExchangeMap} ->
              case parse_req_data(SrpcHttpReqValidationData) of
                {ok, ReqValidationData} ->
                  UserId = maps:get(entityId, ExchangeMap),
                  RespValidationData = 
                    srpc_app_hook:user_key_validation_data(UserId, ReqValidationData),
                  SrpcHttpRespData = create_resp_data(<<>>, RespValidationData),
                  case srpc_lib:user_key_create_validation_response(CryptKeyMap, ExchangeMap,
                                                                    ClientChallenge,
                                                                    SrpcHttpRespData) of
                    {ok, KeyMap, ValidationResponse} ->
                      srpc_app_hook:put(user_key, UserKeyId, maps:put(keyId, UserKeyId, KeyMap)),
                      {ok, ValidationResponse};
                    {invalid, _KeyMap, ValidationResponse} ->
                      %% CxTBD Report invalid
                      {ok, ValidationResponse}
                  end;
                Error ->
                  Error
              end;
            undefined ->
              SrpcHttpRespData = create_resp_data(<<>>, <<>>),
              {_, _KeyMap, ValidationResponse} =
                srpc_lib:user_key_create_validation_response(CryptKeyMap, invalid,
                                                             ClientChallenge, SrpcHttpRespData),
              {ok, ValidationResponse}
          end
      end;
    Error ->
      Error
  end.

%%================================================================================================
%%
%% Key Invalidate
%%
%%================================================================================================
key_invalidate(KeyId, InvalidateRequest) ->
  case key_map_for_key_id(KeyId) of
    {ok, KeyMap} ->
      EntityId = maps:get(entityId, KeyMap),
      case decrypt_data(KeyMap, InvalidateRequest) of
        {ok, EntityId} ->
          KeyType = maps:get(keyType, KeyMap),
          srpc_app_hook:delete(KeyType, KeyId),
          encrypt_data(KeyMap, EntityId);
        {ok, _EntityId} ->
          {error, <<"Invalidate KeyId using invalid entityId">>};
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
server_epoch(KeyId, ServerEpochRequest) ->
  case key_map_for_key_id(KeyId) of
    {ok, KeyMap} ->
      case srpc_encryptor:decrypt(KeyMap, ServerEpochRequest) of
        {ok, <<RandomStamp/binary>>} ->
          DataEpoch = erlang:system_time(seconds),
          RespData = <<DataEpoch:?EPOCH_BITS, RandomStamp/binary>>,
          srpc_encryptor:encrypt(KeyMap, RespData);
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
key_map_for_key_id(KeyId) ->
  case srpc_app_hook:get(lib_key, KeyId) of
    {ok, KeyMap} ->
      {ok, KeyMap};
    undefined ->
      case srpc_app_hook:get(user_key, KeyId) of
        {ok, KeyMap} ->
          {ok, KeyMap};
        undefined ->
          {error, <<"No Key Map for KeyId: ", KeyId/binary>>}
      end
  end.


%%================================================================================================
%%
%% Encrypt / Decrypt
%%
%%================================================================================================
encrypt_data(KeyMap, Data) ->
  SrpcHttpData = create_resp_data(<<>>, Data),
  srpc_lib:encrypt(KeyMap, SrpcHttpData).

decrypt_data(KeyMap, Data) ->
  case srpc_lib:decrypt(KeyMap, Data) of
    {ok, SrpcHttpData} ->
      parse_req_data(SrpcHttpData);
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
  {error, <<"Invalid Srpc Http version number">>};
parse_req_data(_HttpReqData) ->
  {error, <<"Invalid HTTP request data">>}.

%%------------------------------------------------------------------------------------------------
%%
%%
%%
%%------------------------------------------------------------------------------------------------
create_resp_data(SrpcHttpData, RespData) ->
  ServerEpoch = erlang:system_time(seconds),
  << ?DATA_HDR_VSN:?DATA_HDR_BITS, ServerEpoch:?EPOCH_BITS, SrpcHttpData/binary, RespData/binary >>.
