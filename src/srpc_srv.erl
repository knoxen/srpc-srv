-module(srpc_srv).

-author("paul@knoxen.com").

%%
%% CxNote Current implementation uses an explicit app_srpc_handler module that must be provided
%% by the hosting application. Need to allow this module to be passed in some manner to avoid
%% the explicit, hard-coded module name.
%%


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

-define(HDR_VSN,     1).
-define(HDR_BITS,    8).
-define(EPOCH_BITS, 32).
-define(NONCE_BITS,  8).

-define(LIB_KEY_VAL_EPOCH, <<255,255,255,255>>).

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
      RespExchangeData = 
        case erlang:function_exported(app_srpc_handler, lib_key_exchange_data, 1) of
          true ->
            app_srpc_handler:lib_key_exchange_data(ReqExchangeData);
          false ->
            <<>>
        end,
      case srpc_lib:lib_key_create_exchange_response(ClientPublicKey, RespExchangeData) of
        {ok, {ExchangeMap, ExchangeResponse}} ->
          ClientId = maps:get(client_id, ExchangeMap),
          case app_srpc_handler:put(ClientId, ExchangeMap, exchange) of
            ok ->
              {ok, ExchangeResponse};
            Error ->
              Error
          end;
        Error ->
          Error
      end;
    InvalidError ->
      InvalidError
  end.

%%------------------------------------------------------------------------------------------------
%%
%%   Lib Key Validate
%%
%%------------------------------------------------------------------------------------------------
lib_key_validate(ClientId, ValidationRequest) ->
  case app_srpc_handler:get(ClientId, exchange) of
    {ok, ExchangeMap} ->
      app_srpc_handler:delete(ClientId, exchange),
      case srpc_lib:lib_key_process_validation_request(ExchangeMap, ValidationRequest) of
        {ok, {_ReqClientId, ClientChallenge, SrpcReqData}} ->
          case extract_req_data(SrpcReqData) of
            {ok, ValidationReqData} ->
              ValidationRespData = 
                case erlang:function_exported(app_srpc_handler, lib_key_validation_data, 1) of
                  true ->
                    app_srpc_handler:lib_key_validation_data(ValidationReqData);
                  false ->
                    <<>>
                end,
              SrpcRespData = create_srpc_resp_data(ValidationRespData),
              case srpc_lib:lib_key_create_validation_response(ExchangeMap, ClientChallenge,
                                                               SrpcRespData) of
                {ok, ClientMap, ValidationResponse} ->
                  case app_srpc_handler:put(ClientId, ClientMap, lib) of
                    ok ->
                      {ok, ValidationResponse};
                    Error ->
                      Error
                  end;
                {invalid, _ClientMap, ValidationResponse} ->
                  {ok, ValidationResponse};
                Error ->
                  Error
              end;
            Invalid ->
              Invalid
          end;
        Error ->
          Error
      end;
    undefined ->
      {invalid, <<"No exchange info for Client Id: ", ClientId/binary>>}
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
          UserId = maps:get(user_id, SrpcUserData),
          case extract_req_data(SrpcReqData) of
            {ok, ReqRegistrationData} ->
              RespRegistrationData = 
                case erlang:function_exported(app_srpc_handler, registration_data, 2) of
                  true ->
                    app_srpc_handler:registration_data(UserId, ReqRegistrationData);
                  false ->
                    <<>>
                end,
              SrpcRespData = create_srpc_resp_data(RespRegistrationData),
              case RegistrationCode of
                ?SRPC_REGISTRATION_CREATE ->
                  case app_srpc_handler:get(UserId, registration) of
                    undefined ->
                      case app_srpc_handler:put(UserId, SrpcUserData, registration) of
                        ok ->
                          srpc_lib:create_registration_response(ClientMap,
                                                                ?SRPC_REGISTRATION_OK,
                                                                SrpcRespData);
                        _Error ->
                          srpc_lib:create_registration_response(ClientMap,
                                                                ?SRPC_REGISTRATION_ERROR,
                                                                SrpcRespData)
                      end;
                    {ok, _SrpcUserData} ->
                      srpc_lib:create_registration_response(ClientMap,
                                                            ?SRPC_REGISTRATION_DUP,
                                                            SrpcRespData)
                  end;
                ?SRPC_REGISTRATION_UPDATE ->
                  case app_srpc_handler:get(UserId, registration) of
                    {ok, SrpcUserData} ->
                      case app_srpc_handler:put(UserId, SrpcUserData, registration) of
                        ok ->
                          srpc_lib:create_registration_response(ClientMap,
                                                                ?SRPC_REGISTRATION_OK,
                                                                SrpcRespData);
                        _Error ->
                          srpc_lib:create_registration_response(ClientMap,
                                                                ?SRPC_REGISTRATION_ERROR,
                                                                SrpcRespData)
                      end;
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
            Invalid ->
              Invalid
          end;
        Error ->
          Error
      end;
    {invalid, Reason} ->
      {error, Reason}
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
          case extract_req_data(SrpcReqData) of
            {ok, ReqExchangeData} ->
              case app_srpc_handler:get(UserId, registration) of
                {ok, SrpcUserData} ->
                  RespExchangeData = 
                    case erlang:function_exported(app_srpc_handler, user_key_exchange_data, 2) of
                      true ->
                        app_srpc_handler:user_key_exchange_data(UserId, ReqExchangeData);
                      false ->
                        <<>>
                    end,
                  SrpcRespData = create_srpc_resp_data(RespExchangeData),
                  case srpc_lib:user_key_create_exchange_response(CryptClientMap,
                                                                  SrpcUserData,
                                                                  ClientPublicKey, 
                                                                  SrpcRespData) of
                    {ok, {ExchangeMap, ExchangeResponse}} ->
                      ExchangeClientId = maps:get(client_id, ExchangeMap),
                      case app_srpc_handler:put(ExchangeClientId, ExchangeMap, exchange) of
                        ok ->
                          {ok, ExchangeResponse};
                        Error ->
                          Error
                      end;
                    Error ->
                      Error
                  end;
                undefined ->
                  srpc_lib:user_key_create_exchange_response(CryptClientMap, invalid, 
                                                             ClientPublicKey, UserId)
              end;
            InvalidError ->
              InvalidError
          end;
        Error ->
          Error
      end;
    Invalid ->
      Invalid
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
          case app_srpc_handler:get(UserClientId, exchange) of
            {ok, ExchangeMap} ->
              app_srpc_handler:delete(UserClientId, exchange),
              case extract_req_data(SrpcReqValidationData) of
                {ok, ReqValidationData} ->
                  UserId = maps:get(entity_id, ExchangeMap),
                  RespValidationData = 
                    case erlang:function_exported(app_srpc_handler, user_key_validation_data, 2) of
                      true ->
                        app_srpc_handler:user_key_validation_data(UserId, ReqValidationData);
                      false ->
                        <<>>
                    end,
                  SrpcRespData = create_srpc_resp_data(RespValidationData),
                  case srpc_lib:user_key_create_validation_response(CryptClientMap, ExchangeMap,
                                                                    ClientChallenge,
                                                                    SrpcRespData) of
                    {ok, ClientMap, ValidationResponse} ->
                      ClientMap2 = maps:put(client_id, UserClientId, ClientMap),
                      case app_srpc_handler:put(UserClientId, ClientMap2, user) of
                        ok ->
                          {ok, ValidationResponse};
                        Error ->
                          Error
                      end;
                    {invalid, _ClientMap, ValidationResponse} ->
                      %% CxTBD Report invalid
                      {ok, ValidationResponse}
                  end;
                InvalidError ->
                  InvalidError
              end;
            undefined ->
              SrpcRespData = create_srpc_resp_data(<<>>),
              {_, _ClientMap, ValidationResponse} =
                srpc_lib:user_key_create_validation_response(CryptClientMap, invalid,
                                                             ClientChallenge, SrpcRespData),
              {ok, ValidationResponse}
          end
      end;
    Invalid ->
      Invalid
  end.

%%================================================================================================
%%
%% Client Invalidate
%%
%%================================================================================================
invalidate(ClientId, InvalidateRequest) ->
  case client_map_for_id(ClientId) of
    {ok, ClientMap} ->
      case decrypt_data(ClientMap, InvalidateRequest) of
        {ok, ClientId} ->
          ClientType = maps:get(client_type, ClientMap),
          app_srpc_handler:delete(ClientId, ClientType),
          encrypt_data(ClientMap, ClientId);
        {ok, _ClientId} ->
          {error, <<"Attempt to invalidate another ClientId">>};
        Error ->
          Error
      end;
    Invalid ->
      Invalid
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
          DataEpoch = epoch_seconds(),
          RespData = <<DataEpoch:?EPOCH_BITS, RandomStamp/binary>>,
          srpc_encryptor:encrypt(ClientMap, RespData);
        {ok, _ReqData} ->
          {error, <<"Invalid data epoch stamp">>};
        Error ->
          Error
      end;
    Invalid ->
      Invalid
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
  case app_srpc_handler:get(ClientId, lib) of
    undefined ->
      case app_srpc_handler:get(ClientId, user) of
        undefined ->
          case app_srpc_handler:get(ClientId, exchange) of
            undefined ->
              {invalid, <<"Invalid ClientId: ", ClientId/binary>>};
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
  SrpcData = create_srpc_resp_data(Data),
  srpc_lib:encrypt(ClientMap, SrpcData).

decrypt_data(ClientMap, Data) ->
  case srpc_lib:decrypt(ClientMap, Data) of
    {ok, SrpcData} ->
      extract_req_data(SrpcData);
    InvalidError ->
      InvalidError
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
extract_req_data(<<?HDR_VSN:?HDR_BITS, ReqEpoch:?EPOCH_BITS, NonceLen:?NONCE_BITS,
                   MoreData/binary>>) ->
  {Nonce, ReqData} = 
    case NonceLen of
      0 ->
        {<<"">>, MoreData};
      _ ->
        case MoreData of
          <<NonceData:NonceLen/binary, Data/binary>> ->
            erlang:put(nonce, NonceData),
            {NonceData, Data};
          _ ->
            {error, <<"Invalid nonce len longer than available data">>}
        end
    end,

  <<LibKeyValEpoch:?EPOCH_BITS>> = ?LIB_KEY_VAL_EPOCH,
  case ReqEpoch =:= LibKeyValEpoch of
    true ->
      {ok, ReqData};
    false ->
      case application:get_env(srpc_srv, req_age_tolerance) of
        {ok, 0} ->
          {ok, ReqData};
        {ok, Tolerance} ->
          SysEpoch = epoch_seconds(),
          case abs(SysEpoch - ReqEpoch) =< Tolerance of
            true ->
              case NonceLen of
                0 ->
                  {ok, ReqData};
                _ ->
                  case Nonce of
                    error ->
                      {Nonce, ReqData};
                    _ ->
                      case erlang:function_exported(app_srpc_handler, nonce, 1) of
                        true ->
                          case app_srpc_handler:nonce(Nonce) of
                            true ->
                              {ok, ReqData};
                            false ->
                              {invalid, <<"Repeat nonce: ", Nonce/binary>>}
                          end;
                        false ->
                          {ok, ReqData}
                      end
                  end
              end;
            false ->
              {invalid, <<"Request age exceeds tolerance">>}
          end
      end
  end;
extract_req_data(<<_:?HDR_BITS, _Rest/binary>>) ->
  {error, <<"Invalid Srpc data version number">>};
extract_req_data(_SrpcReqData) ->
  {error, <<"Invalid Srpc request data">>}.

%%------------------------------------------------------------------------------------------------
%%
%%
%%
%%------------------------------------------------------------------------------------------------
create_srpc_resp_data(RespData) ->
  Epoch = epoch_seconds(),
  Nonce = 
    case erlang:get(nonce) of
      undefined ->
        <<>>;
      Value ->
        Value
    end,
  NonceLen = erlang:byte_size(Nonce),
  <<?HDR_VSN:?HDR_BITS, Epoch:?EPOCH_BITS, NonceLen:?NONCE_BITS, Nonce/binary, RespData/binary>>.

epoch_seconds() ->
  erlang:system_time(seconds).
