-module(srpc_http).

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
        ]).

-define(APP_NAME, srpc_http).

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
        {ok, {ClientChallenge, ReqValidationData}} ->
          RespValidationData = srpc_app_hook:lib_key_validation_data(ReqValidationData),
          case srpc_lib:lib_key_create_validation_response(ExchangeMap, ClientChallenge,
                                                           RespValidationData) of
            {ok, KeyMap, ValidationResponse} ->
              srpc_app_hook:put(lib_key, KeyId, KeyMap),
              {ok, ValidationResponse};
            {invalid, KeyMap, ValidationResponse} ->
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
  case key_map_for_id(KeyId) of
    {ok, KeyInfo} ->
      case srpc_lib:process_registration_request(KeyInfo, RegistrationRequest) of
        {ok, {RegistrationCode, SrpUserData, SrpcHttpReqData}} ->
          UserId = maps:get(srpId, SrpUserData),
          case parse_req_data(SrpcHttpReqData) of
            {ok, ReqRegistrationData} ->
              RespRegistrationData = srpc_app_hook:registration_data(UserId, ReqRegistrationData),
              SrpcHttpRespData = create_resp_data(<<>>, RespRegistrationData),
              case RegistrationCode of
                ?SRPC_REGISTRATION_CREATE ->
                  case srpc_app_hook:get(srpc_user, UserId) of
                    undefined ->
                      srpc_app_hook:put(srpc_user, UserId, SrpUserData),
                      srpc_lib:create_registration_response(KeyInfo,
                                                            ?SRPC_REGISTRATION_OK,
                                                            SrpcHttpRespData);
                    {ok, _SrpUserData} ->
                      srpc_lib:create_registration_response(KeyInfo,
                                                            ?SRPC_REGISTRATION_DUP,
                                                            SrpcHttpRespData)
                  end;
                ?SRPC_REGISTRATION_UPDATE ->
                  case srpc_app_hook:get(srpc_user, UserId) of
                    {ok, _SrpUserData} ->
                      srpc_app_hook:put(srpc_user, UserId, SrpUserData),
                      srpc_lib:create_registration_response(KeyInfo,
                                                            ?SRPC_REGISTRATION_OK,
                                                            SrpcHttpRespData);
                    undefined ->
                      srpc_lib:create_registration_response(KeyInfo,
                                                            ?SRPC_REGISTRATION_NOT_FOUND,
                                                            SrpcHttpRespData)
                  end;
                _ ->
                  srpc_lib:create_registration_response(KeyInfo,
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
user_key_exchange(KeyId, ExchangeRequest) ->
  case key_map_for_id(KeyId) of
    {ok, KeyMap} ->
      case srpc_lib:user_key_process_exchange_request(KeyMap, ExchangeRequest) of
        {ok, {UserId, ClientPublicKey, SrpcHttpReqData}} ->
          case parse_req_data(SrpcHttpReqData) of
            {ok, ReqExchangeData} ->
              case srpc_app_hook:get(srpc_user, UserId) of
                {ok, SrpUserData} ->
                  RespExchangeData = srpc_app_hook:user_key_exchange_data(UserId, ReqExchangeData),

                  SrpcHttpData = <<>>,
                  SrpcHttpRespData = create_resp_data(SrpcHttpData, RespExchangeData),

                  case srpc_lib:user_key_create_exchange_response(KeyMap,
                                                                  SrpUserData,
                                                                  ClientPublicKey, 
                                                                  SrpcHttpRespData) of
                    {ok, {ExchangeMap, ExchangeResponse}} ->
                      KeyId = maps:get(keyId, ExchangeMap),
                      srpc_app_hook:put(exchange_info, KeyId, ExchangeMap),
                      {ok, ExchangeResponse};
                    Error ->
                      Error
                  end;
                undefined ->
                  srpc_lib:user_key_create_exchange_response(KeyMap, invalid, 
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

user_key_validate(KeyId, ValidationRequest) ->
  case key_map_for_id(KeyId) of
    {ok, KeyMap} ->
      case srpc_lib:user_key_process_validation_request(KeyMap, ValidationRequest) of
        {ok, {UserKeyId, ClientChallenge, SrpcHttpReqData}} ->
          case srpc_app_hook:get(exchange_info, UserKeyId) of
            {ok, ExchangeMap} ->
              case parse_req_data(SrpcHttpReqData) of
                {ok, ReqValidationData} ->
                  UserId = maps:get(entityId, ExchangeMap),
                  RespValidationData = srpc_app_hook:user_key_validation_data(UserId, 
                                                                              ReqValidationData),
                  {Len, KeyId} = rand_key_id(),
                  SrpcHttpData = <<Len, KeyId/binary>>,
                  SrpcHttpRespData = create_resp_data(SrpcHttpData, RespValidationData),
                  ExchangeMap2 = maps:put(keyId, KeyId, ExchangeMap),
                  case srpc_lib:user_key_create_validation_response(KeyMap, ExchangeMap2,
                                                                    ClientChallenge,
                                                                    SrpcHttpRespData) of
                    {ok, KeyMap, ValidationResponse} ->
                      maps:put(keyId, KeyId, KeyMap),
                      srpc_app_hook:put(user_key, KeyId, KeyMap),
                      {ok, ValidationResponse};
                    {invalid, _KeyMap, ValidationResponse} ->
                      %% CxTBD Report invalid
                      {ok, ValidationResponse}
                  end;
                Error ->
                  Error
              end;
            undefined ->
              SrpcId = srpc_lib:srpc_id(),
              case UserKeyId of
                SrpcId ->
                  {Len, KeyId} = rand_key_id(),
                  SrpcHttpData = <<Len, KeyId/binary>>,
                  SrpcHttpRespData = create_resp_data(SrpcHttpData, <<>>),
                  srpc_lib:user_key_create_validation_response(KeyMap, invalid,
                                                               ClientChallenge, SrpcHttpRespData);
                _ ->
                  {error, <<"No User Key data for UserKeyId: ", UserKeyId/binary>>}
              end
          end;
        Error ->
          Error
      end;
    Error ->
      Error
  end.

%%================================================================================================
%%================================================================================================
server_epoch(KeyId, Body) ->
  case key_map_for_id(KeyId) of
    {ok, KeyMap} ->
      case srpc_encryptor:decrypt(KeyMap, Body) of
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
%%================================================================================================
encrypt_data(KeyMap, ResponseData) ->
  SrpcHttpRespData = create_resp_data(<<>>, ResponseData),
  srpc_lib:encrypt(KeyMap, SrpcHttpRespData).

decrypt_data(KeyMap, RequestData) ->
  case srpc_lib:decrypt(KeyMap, RequestData) of
    {ok, SrpcHttpReqData} ->
      parse_req_data(SrpcHttpReqData);
    Error ->
      Error
  end.

%%================================================================================================
%% Private functions
%%================================================================================================
key_map_for_id(KeyId) ->
  case srpc_app_hook:get(lib_key, KeyId) of
    {ok, KeyMap} ->
      {ok, KeyMap};
    undefined ->
      {error, <<"No Lib Key for KeyId: ", KeyId/binary>>}
  end.

req_age_tolerance() ->
  case application:get_env(req_age_tolerance) of
    {ok, AgeTolerance} ->
      AgeTolerance;
    undefined ->
      {ok, AgeTolerance} = application:get_env(?APP_NAME, req_age_tolerance),
      AgeTolerance
  end.

rand_key_id() ->
  KeyIdLen = 
    case application:get_env(key_id_len) of
      {ok, Len} ->
        Len;
      undefined ->
        {ok, Len} = application:get_env(?APP_NAME, key_id_len),
        Len
    end,
  {KeyIdLen, srpc_util:rand_id(KeyIdLen)}.

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

create_resp_data(SrpcHttpData, RespData) ->
  ServerEpoch = erlang:system_time(seconds),
  << ?DATA_HDR_VSN:?DATA_HDR_BITS, ServerEpoch:?EPOCH_BITS, SrpcHttpData/binary, RespData/binary >>.
