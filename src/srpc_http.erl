-module(srpc_http).

-author("paul@knoxen.com").

%% API exports
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

%%
%% Registration Codes
%%
-define(SRPC_REGISTRATION_CREATE,      1).
-define(SRPC_REGISTRATION_UPDATE,      2).
-define(SRPC_REGISTRATION_OK,         10).
-define(SRPC_REGISTRATION_DUP,        11).
-define(SRPC_REGISTRATION_NOT_FOUND,  12).
-define(SRPC_REGISTRATION_ERROR,     255).

%%====================================================================
%% API functions
%%====================================================================
lib_key_exchange(ExchangeRequest) ->
  case srpc_lib:lib_key_process_exchange_request(ExchangeRequest) of 
    {ok, {ClientPublicKey, ReqData}} ->
      RespData = srpc_app_hook:lib_key_exchange_data(ReqData),
      case srpc_lib:lib_key_create_exchange_response(ClientPublicKey, RespData) of
        {ok, {SrpData, RespPacket}} ->
          LibKeyId = maps:get(keyId, SrpData),
          srpc_app_hook:put(srp_data, LibKeyId, SrpData),
          {ok, RespPacket};
        Error ->
          Error
      end;
    Error ->
      Error
  end.

lib_key_validate(LibKeyId, ValidationRequest) ->
  case srpc_app_hook:get(srp_data, LibKeyId) of
    {ok, SrpData} ->
      case srpc_lib:lib_key_process_validation_request(SrpData, ValidationRequest) of
        {ok, {LibKeyInfo, ClientChallenge, ReqData}} ->
          RespData = srpc_app_hook:lib_key_validation_data(ReqData),
          case srpc_lib:lib_key_create_validation_response(SrpData, LibKeyInfo,
                                                           ClientChallenge, RespData) of
            {ok, RespPacket} ->
              srpc_app_hook:put(lib_key, LibKeyId, LibKeyInfo),
              {ok, RespPacket};
            {invalid, RespPacket} ->
              %% CxTBD Log/report invalid result
              {ok, RespPacket};
            Error ->
              Error
          end;
        Error ->
          Error
      end;
    undefined ->
      {error, <<"No SRP Data for Lib Key Id: ", LibKeyId/binary>>}
  end.

user_registration(LibKeyId, RegistrationRequest) ->
  case lib_key_data_for_id(LibKeyId) of
    {ok, LibKeyInfo} ->
      case srpc_lib:process_registration_request(LibKeyInfo, RegistrationRequest) of
        {ok, {RegistrationCode, SrpUserData, SrpcHttpReqData}} ->
          UserId = maps:get(srpId, SrpUserData),
          case parse_req_data(SrpcHttpReqData) of
            {ok, ReqData} ->
              RespData = srpc_app_hook:registration_data(UserId, ReqData),
              SrpcHttpRespData = create_resp_data(<<>>, RespData),
              case RegistrationCode of
                ?SRPC_REGISTRATION_CREATE ->
                  case srpc_app_hook:get(srp_user, UserId) of
                    undefined ->
                      srpc_app_hook:put(srp_user, UserId, SrpUserData),
                      srpc_lib:create_registration_response(LibKeyInfo,
                                                            ?SRPC_REGISTRATION_OK,
                                                            SrpcHttpRespData);
                    {ok, _SrpUserData} ->
                      srpc_lib:create_registration_response(LibKeyInfo,
                                                            ?SRPC_REGISTRATION_DUP,
                                                            SrpcHttpRespData)
                  end;
                ?SRPC_REGISTRATION_UPDATE ->
                  case srpc_app_hook:get(srp_user, UserId) of
                    {ok, _SrpUserData} ->
                      srpc_app_hook:put(srp_user, UserId, SrpUserData),
                      srpc_lib:create_registration_response(LibKeyInfo,
                                                            ?SRPC_REGISTRATION_OK,
                                                            SrpcHttpRespData);
                    undefined ->
                      srpc_lib:create_registration_response(LibKeyInfo,
                                                            ?SRPC_REGISTRATION_NOT_FOUND,
                                                            SrpcHttpRespData)
                  end;
                _ ->
                  srpc_lib:create_registration_response(LibKeyInfo,
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

user_key_exchange(LibKeyId, ExchangeRequest) ->
  io:format("~p user_key_exchange~n", [?MODULE]),

  case lib_key_data_for_id(LibKeyId) of
    {ok, LibKeyInfo} ->
      case srpc_lib:user_key_process_exchange_request(LibKeyInfo, ExchangeRequest) of
        {ok, {UserId, ClientPublicKey, SrpcHttpReqData}} ->
          io:format("  UserId: ~p~n", [UserId]),
          io:format("  SrpcHttpReqData: ~p~n", [srpc_util:bin_to_hex(SrpcHttpReqData)]),
          case parse_req_data(SrpcHttpReqData) of
            {ok, ReqData} ->
              io:format("  parse exchange data~n"),

              case srpc_app_hook:get(srp_user, UserId) of
                {ok, SrpUserData} ->
                  io:format("  got exchange user info~n"),

                  RespData = srpc_app_hook:user_key_exchange_data(UserId, ReqData),
                  io:format("  RespData~p~n", [RespData]),


                  SrpcHttpData = <<>>,
                  SrpcHttpRespData = create_resp_data(SrpcHttpData, RespData),

                  io:format("  SrpcHttpRespData~p~n", [SrpcHttpRespData]),
                  case srpc_lib:user_key_create_exchange_response(LibKeyInfo,
                                                                  SrpUserData,
                                                                  ClientPublicKey, 
                                                                  SrpcHttpRespData) of
                    {ok, {SrpData, RespPacket}} ->
                      UserKeyId = maps:get(keyId, SrpData),
                      srpc_app_hook:put(srp_data, UserKeyId, SrpData),
                      {ok, RespPacket};
                    Error ->
                      Error
                  end;
                undefined ->
                  srpc_lib:user_key_create_exchange_response(LibKeyInfo, invalid, 
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

user_key_validate(LibKeyId, ValidationRequest) ->
  case lib_key_data_for_id(LibKeyId) of
    {ok, LibKeyInfo} ->
      case srpc_lib:user_key_process_validation_request(LibKeyInfo, ValidationRequest) of
        {ok, {UserKeyId, ClientChallenge, SrpcHttpReqData}} ->
          case srpc_app_hook:get(srp_data, UserKeyId) of
            {ok, SrpData} ->
              case parse_req_data(SrpcHttpReqData) of
                {ok, ReqData} ->
                  UserId = maps:get(entityId, SrpData),
                  RespData = srpc_app_hook:user_key_validation_data(UserId, ReqData),
                  {Len, SessionId} = rand_session_id(),
                  SrpcHttpData = <<Len, SessionId/binary>>,
                  SrpcHttpRespData = create_resp_data(SrpcHttpData, RespData),
                  SrpData2 = maps:put(keyId, SessionId, SrpData),
                  case srpc_lib:user_key_create_validation_response(LibKeyInfo, SrpData2,
                                                                    ClientChallenge,
                                                                    SrpcHttpRespData) of
                    {ok, UserKeyInfo, RespPacket} ->
                      maps:put(sessionId, SessionId, UserKeyInfo),
                      srpc_app_hook:put(user_key, SessionId, UserKeyInfo),
                      {ok, RespPacket};
                    {invalid, _UserKeyInfo, RespPacket} ->
                      %% CxTBD Report invalid
                      {ok, RespPacket}
                  end;
                Error ->
                  Error
              end;
            undefined ->
              SrpcId = srpc_lib:srpc_id(),
              case UserKeyId of
                SrpcId ->
                  {Len, SessionId} = rand_session_id(),
                  SrpcHttpData = <<Len, SessionId/binary>>,
                  SrpcHttpRespData = create_resp_data(SrpcHttpData, <<>>),
                  srpc_lib:user_key_create_validation_response(LibKeyInfo, invalid,
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

server_epoch(LibKeyId, Body) ->
  case lib_key_data_for_id(LibKeyId) of
    {ok, LibKeyInfo} ->
      case srpc_encryptor:decrypt(LibKeyInfo, Body) of
        {ok, <<RandomStamp/binary>>} ->
          DataEpoch = erlang:system_time(seconds),
          RespData = <<DataEpoch:?EPOCH_BITS, RandomStamp/binary>>,
          srpc_encryptor:encrypt(LibKeyInfo, RespData);
        {ok, _ReqData} ->
          {error, <<"Invalid data epoch stamp">>};
        Error ->
          Error
      end;
    Error ->
      Error
  end.    

encrypt_data(KeyInfo, ResponseData) ->
  SrpcHttpRespData = create_resp_data(<<>>, ResponseData),
  srpc_lib:encrypt(KeyInfo, SrpcHttpRespData).

decrypt_data(KeyInfo, RequestData) ->
  case srpc_lib:decrypt(KeyInfo, RequestData) of
    {ok, SrpcHttpReqData} ->
      parse_req_data(SrpcHttpReqData);
    Error ->
      Error
  end.

%%====================================================================
%% Internal functions
%%====================================================================
lib_key_data_for_id(LibKeyId) ->
  case srpc_app_hook:get(lib_key, LibKeyId) of
    {ok, LibKeyInfo} ->
      DataKeyId = maps:get(keyId, LibKeyInfo),
      case LibKeyId =:= DataKeyId of
        true ->
          {ok, LibKeyInfo};
        false ->
          {error, <<"Invalid mapping DataKeyId: ", DataKeyId/binary,
                    " != LibKeyId: ", LibKeyId/binary>>}
      end;
    undefined ->
      {error, <<"No Lib Key for KeyId: ", LibKeyId/binary>>}
  end.

req_age_tolerance() ->
  case application:get_env(req_age_tolerance) of
    {ok, AgeTolerance} ->
      AgeTolerance;
    undefined ->
      {ok, AgeTolerance} = application:get_env(?APP_NAME, req_age_tolerance),
      AgeTolerance
  end.

rand_session_id() ->
  SidLen = 
    case application:get_env(sid_len) of
      {ok, Len} ->
        Len;
      undefined ->
        {ok, Len} = application:get_env(?APP_NAME, sid_len),
        Len
    end,
  {SidLen, srpc_util:rand_id(SidLen)}.

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
