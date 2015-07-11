-module(srpcryptor_pro).

-author("paul@knoxen.com").

%% API exports
-export([lib_key/1
        ,validate_lib_key/2
        ,register/2
        ,login/2
        ,validate_login/2
        ,encrypt_data/2
        ,decrypt_packet/2 
        ,epoch/2
        ]).

-define(APP_NAME, srpcryptor_pro).

-define(PRO_VSN,            1).

-define(PRO_VSN_BITS,       8).
-define(EPOCH_BITS,        32).

-define(SESSION_KEY_BYTES, 32).
-define(CHALLENGE_BYTES,   32).

-define(EPOCH_STAMP_BYTES, 16).

%%====================================================================
%% API functions
%%====================================================================
lib_key(LibKeyPacket) ->
  case srpcryptor_lib:lib_key_packet_data(LibKeyPacket) of 
    {ok, {ClientPublicKey, ReqData}} ->
      RespData = srpcryptor_api_impl:lib_key_response_data(ReqData),
      case srpcryptor_lib:lib_key_response_packet(ClientPublicKey, RespData) of
        {ok, {SrpData, RespPacket}} ->
          LibKeyId = maps:get(keyId, SrpData),
          srpcryptor_api_impl:put(srp_data, LibKeyId, SrpData),
          {ok, RespPacket};
        Error ->
          Error
      end;
    Error ->
      Error
  end.

validate_lib_key(LibKeyId, ValidatePacket) ->
  case srpcryptor_api_impl:get(srp_data, LibKeyId) of
    {ok, SrpData} ->
      case srpcryptor_lib:lib_key_validate_packet_data(SrpData, ValidatePacket) of
        {ok, {LibKeyData, ClientChallenge, ReqData}} ->
          RespData = srpcryptor_api_impl:lib_key_validation_response_data(ReqData),
          EpochSeconds = srpcryptor_util:epoch_seconds(),
          ProRespData = <<EpochSeconds:?EPOCH_BITS, RespData/binary>>,
          case srpcryptor_lib:lib_key_validation_response_packet(SrpData, LibKeyData,
                                                                 ClientChallenge, ProRespData) of
            {ok, RespPacket} ->
              srpcryptor_api_impl:put(lib_key, LibKeyId, LibKeyData),
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

register(LibKeyId, RegistrationPacket) ->
  case lib_key_data_for_id(LibKeyId) of
    {ok, LibKeyData} ->
      case srpcryptor_lib:registration_packet_data(LibKeyData, RegistrationPacket) of
        {ok, {SrpUserData, ProReqData}} ->
          case parse_pro_req_data(ProReqData) of
            {ok, ReqData} ->
              SrpId = maps:get(srpId, SrpUserData),
              RespData = srpcryptor_api_impl:registration_response_data(SrpId, ReqData),
              ProData = <<>>,
              ProRespData = create_pro_resp_data(ProData, RespData),
              case srpcryptor_api_impl:get(srp_user, SrpId) of
                undefined ->
                  srpcryptor_api_impl:put(srp_user, SrpId, SrpUserData),
                  srpcryptor_lib:registration_response_packet(ok, LibKeyData, ProRespData);
                {ok, _SrpUserData} ->
                  srpcryptor_lib:registration_response_packet(duplicate, LibKeyData, ProRespData)
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

login(LibKeyId, LoginPacket) ->
  case lib_key_data_for_id(LibKeyId) of
    {ok, LibKeyData} ->
      case srpcryptor_lib:login_packet_data(LibKeyData, LoginPacket) of
        {ok, {SrpId, ClientPublicKey, ProReqData}} ->
          case parse_pro_req_data(ProReqData) of
            {ok, ReqData} ->
              case srpcryptor_api_impl:get(srp_user, SrpId) of
                {ok, SrpUserData} ->
                  RespData = srpcryptor_api_impl:login_response_data(SrpId, ReqData),
                  ProData = <<>>,
                  ProRespData = create_pro_resp_data(ProData, RespData),
                  case srpcryptor_lib:login_response_packet(LibKeyData, SrpUserData,
                                                            ClientPublicKey, ProRespData) of
                    {ok, {SrpData, RespPacket}} ->
                      LoginKeyId = maps:get(keyId, SrpData),
                      srpcryptor_api_impl:put(srp_data, LoginKeyId, SrpData),
                      {ok, RespPacket};
                    Error ->
                      Error
                  end;
                undefined ->
                  srpcryptor_lib:login_response_packet(LibKeyData, invalid, ClientPublicKey, SrpId)
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

validate_login(LibKeyId, ValidatePacket) ->
  case lib_key_data_for_id(LibKeyId) of
    {ok, LibKeyData} ->
      case srpcryptor_lib:login_validate_packet_data(LibKeyData, ValidatePacket) of
        {ok, {LoginKeyId, ClientChallenge, ProReqData}} ->
          case srpcryptor_api_impl:get(srp_data, LoginKeyId) of
            {ok, SrpData} ->
              case parse_pro_req_data(ProReqData) of
                {ok, ReqData} ->
                  SrpId = maps:get(entityId, SrpData),
                  RespData = srpcryptor_api_impl:login_validation_response_data(SrpId, ReqData),
                  {Len, SessionId} = rand_session_id(),
                  ProData = <<Len, SessionId/binary>>,
                  ProRespData = create_pro_resp_data(ProData, RespData),
                  SrpData2 = maps:put(keyId, SessionId, SrpData),
                  case srpcryptor_lib:login_validation_response_packet(LibKeyData, SrpData2,
                                                                       ClientChallenge,
                                                                       ProRespData) of
                    {ok, LoginKeyData, RespPacket} ->
                      maps:put(sessionId, SessionId, LoginKeyData),
                      srpcryptor_api_impl:put(login_key, SessionId, LoginKeyData),
                      {ok, RespPacket};
                    {invalid, _LoginKeyData, RespPacket} ->
                      %% CxTBD Report invalid
                      {ok, RespPacket}
                  end;
                Error ->
                  Error
              end;
            undefined ->
              LibId = srpcryptor_lib:lib_id(),
              case LoginKeyId of
                LibId ->
                  {Len, SessionId} = rand_session_id(),
                  ProData = <<Len, SessionId/binary>>,
                  ProRespData = create_pro_resp_data(ProData, <<>>),
                  srpcryptor_lib:login_validation_response_packet(LibKeyData, invalid,
                                                                  ClientChallenge, ProRespData);
                _ ->
                  {error, <<"No Login Key data for LoginKeyId: ", LoginKeyId/binary>>}
              end
          end;
        Error ->
          Error
      end;
    Error ->
      Error
  end.

epoch(LibKeyId, Body) ->
  case lib_key_data_for_id(LibKeyId) of
    {ok, LibKeyData} ->
      case srpcryptor_encryptor:decrypt(LibKeyData, Body) of
        {ok, <<RandomStamp:?EPOCH_STAMP_BYTES/binary>>} ->
          Seconds = srpcryptor_util:epoch_seconds(),
          RespData = <<Seconds:?EPOCH_BITS, RandomStamp/binary>>,
          srpcryptor_encryptor:encrypt(LibKeyData, RespData);
        {ok, _ReqData} ->
          {error, <<"Invalid Epoch stamp">>};
        Error ->
          Error
      end;
    Error ->
      Error
  end.    

encrypt_data(KeyData, RespData) ->
  ProRespData = create_pro_resp_data(<<>>, RespData),
  srpcryptor_lib:encrypt(KeyData, ProRespData).

decrypt_packet(KeyData, Packet) ->
  case srpcryptor_lib:decrypt(KeyData, Packet) of
    {ok, ProReqData} ->
      parse_pro_req_data(ProReqData);
    Error ->
      Error
  end.

%%====================================================================
%% Internal functions
%%====================================================================
lib_key_data_for_id(LibKeyId) ->
  case srpcryptor_api_impl:get(lib_key, LibKeyId) of
    {ok, LibKeyData} ->
      DataKeyId = maps:get(keyId, LibKeyData),
      case LibKeyId =:= DataKeyId of
        true ->
          {ok, LibKeyData};
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
  {SidLen, srpcryptor_util:rand_id(SidLen)}.


parse_pro_req_data(<<?PRO_VSN:?PRO_VSN_BITS, DataEpoch:?EPOCH_BITS, ReqData/binary>>) ->
  Tolerance = req_age_tolerance(),
  Epoch = srpcryptor_util:epoch_seconds(),
  case (Epoch - DataEpoch) < Tolerance of
    true ->
      {ok, ReqData};
    false ->
      {error, <<"Request data age is greater than tolerance">>}
  end;
parse_pro_req_data(<<_:?PRO_VSN_BITS, _Rest/binary>>) ->
  {error, <<"Invalid SRP Cryptor Pro version number">>};
parse_pro_req_data(_ProReqData) ->
  {error, <<"Invalid pro request data">>}.

create_pro_resp_data(ProData, RespData) ->
  EpochSeconds = srpcryptor_util:epoch_seconds(),
  << ?PRO_VSN:8, EpochSeconds:?EPOCH_BITS, ProData/binary, RespData/binary >>.
