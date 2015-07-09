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
  LibId = srpcryptor_lib:lib_id(),
  case srpcryptor_lib:lib_key_packet_data(LibKeyPacket) of 
    {ok, {LibId, ClientPublicKey, ReqData}} ->
      RespData = srpcryptor_api_impl:lib_key_response_data(ReqData),
      case srpcryptor_lib:lib_key_response_packet(ClientPublicKey, RespData) of
        {ok, {KeyReqId, KeyReqData, RespPacket}} ->
          srpcryptor_api_impl:put(key_req, KeyReqId, KeyReqData),
          {ok, RespPacket};
        Error ->
          Error
      end;
    {ok, _InvalidLibId} ->
      {error, <<"Invalid Lib Id">>};
    Error ->
      Error
  end.

validate_lib_key(KeyId, ValidatePacket) ->
  case srpcryptor_api_impl:get(key_req, KeyId) of
    {ok, KeyData} ->
      LibKey = maps:get(key, KeyData),
      HmacKey = crypto:hmac(sha256, LibKey, KeyId),
      KeyInfo = {KeyId, LibKey, HmacKey},
      case srpcryptor_lib:lib_key_validate_packet_data(KeyInfo, ValidatePacket) of
        {ok, {ClientChallenge, ReqData}} ->
          RespData = srpcryptor_api_impl:lib_key_validate_response_data(ReqData),
          EpochSeconds = srpcryptor_util:epoch_seconds(),
          ProRespData = <<EpochSeconds:?EPOCH_BITS, RespData/binary>>,
          case srpcryptor_lib:lib_key_validate_response_packet({KeyId, KeyData, HmacKey},
                                                               ClientChallenge, ProRespData) of
            {ok, RespPacket} ->
              LibKeyData = #{entityId => KeyId
                            ,libKey   => LibKey
                            ,hmacKey  => HmacKey},
              srpcryptor_api_impl:put(lib_key, KeyId, LibKeyData),
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
      {error, <<"No Key Req for KeyId: ", KeyId/binary>>}
  end.

register(KeyId, RegistrationPacket) ->
  case info_for_key_id(KeyId) of
    {ok, KeyInfo} ->
      case srpcryptor_lib:registration_packet_data(KeyInfo, RegistrationPacket) of
        {ok, {RegId, RegData, ProReqData}} ->
          case parse_pro_req_data(ProReqData) of
            {ok, ReqData} ->
              RespData = srpcryptor_api_impl:registration_response_data(RegId, ReqData),
              ProData = <<>>,
              ProRespData = create_pro_resp_data(ProData, RespData),
              case srpcryptor_api_impl:get(srp_user, RegId) of
                undefined ->
                  srpcryptor_api_impl:put(srp_user, RegId, RegData),
                  srpcryptor_lib:registration_response_packet(ok, KeyInfo, ProRespData);
                {ok, _RegData} ->
                  srpcryptor_lib:registration_response_packet(duplicate, KeyInfo, ProRespData)
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

login(KeyId, LoginPacket) ->
  case info_for_key_id(KeyId) of
    {ok, KeyInfo} ->
      case srpcryptor_lib:login_packet_data(KeyInfo, LoginPacket) of
        {ok, {RegId, ClientPublicKey, ProReqData}} ->
          case parse_pro_req_data(ProReqData) of
            {ok, ReqData} ->
              case srpcryptor_api_impl:get(srp_user, RegId) of
                {ok, RegData} ->
                  RespData = srpcryptor_api_impl:login_response_data(RegId, ReqData),
                  ProData = <<>>,
                  ProRespData = create_pro_resp_data(ProData, RespData),
                  RegInfo = {RegId, RegData},
                  case srpcryptor_lib:login_response_packet(KeyInfo, RegInfo,
                                                            ClientPublicKey, ProRespData) of
                    {ok, {KeyReqId, KeyReqData, RespPacket}} ->
                      srpcryptor_api_impl:put(key_req, KeyReqId, KeyReqData),
                      {ok, RespPacket};
                    Error ->
                      Error
                  end;
                undefined ->
                  srpcryptor_lib:login_response_packet(KeyInfo, invalid, ClientPublicKey, RegId)
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

validate_login(KeyId, ValidatePacket) ->
  case info_for_key_id(KeyId) of
    {ok, KeyInfo} ->
      case srpcryptor_lib:login_validate_packet_data(KeyInfo, ValidatePacket) of
        {ok, {ClientChallenge, LoginReqId, ProReqData}} ->
          case srpcryptor_api_impl:get(key_req, LoginReqId) of
            {ok, LoginReqData} ->
              RegId = maps:get(entityId, LoginReqData),
              case parse_pro_req_data(ProReqData) of
                {ok, ReqData} ->
                  case srpcryptor_api_impl:get(srp_user, RegId) of
                    {ok, _RegData} ->
                      RespData = 
                        srpcryptor_api_impl:login_validate_response_data(RegId, ReqData),
                      {Len, SessionId} = rand_session_id(),
                      ProData = <<Len, SessionId/binary>>,
                      ProRespData = create_pro_resp_data(ProData, RespData),
                      case srpcryptor_lib:login_validate_response_packet(KeyInfo,
                                                                         LoginReqData,
                                                                         ClientChallenge,
                                                                         ProRespData) of
                        {ok, RespPacket} ->
                          LoginKey = maps:get(key, LoginReqData),
                          {_KeyId, LibKey, _LibHmacKey} = KeyInfo,
                          HmacKey = crypto:hmac(sha256, LoginKey, LibKey),
                          SessionData = #{entityId   => RegId
                                         ,sessionKey => LoginKey
                                         ,hmacKey    => HmacKey
                                         },
                          srpcryptor_api_impl:put(session_key, SessionId, SessionData),
                          {ok, RespPacket};
                        {invalid, RespPacket} ->
                          %% CxTBD Report invalid
                          {ok, RespPacket}
                      end;
                    undefined ->
                      {error, <<"No registration data for RegId: ", RegId/binary>>}
                  end;
                Error ->
                  Error
              end;
            undefined ->
              LibId = srpcryptor_lib:lib_id(),
              case LoginReqId of
                LibId ->
                  {Len, SessionId} = rand_session_id(),
                  ProData = <<Len, SessionId/binary>>,
                  ProRespData = create_pro_resp_data(ProData, <<>>),
                  srpcryptor_lib:login_validate_response_packet(KeyInfo, invalid,
                                                                ClientChallenge, ProRespData);
                _ ->
                  {error, <<"No Login Req data for KeyReqId: ", LoginReqId/binary>>}
              end
          end;
        Error ->
          Error
      end;
    Error ->
      Error
  end.

epoch(KeyId, Body) ->
  case info_for_key_id(KeyId) of
    {ok, KeyInfo} ->
      case srpcryptor_encryptor:decrypt(KeyInfo, Body) of
        {ok, <<RandomStamp:?EPOCH_STAMP_BYTES/binary>>} ->
          Seconds = srpcryptor_util:epoch_seconds(),
          RespData = <<Seconds:?EPOCH_BITS, RandomStamp/binary>>,
          srpcryptor_encryptor:encrypt(KeyInfo, RespData);
        {ok, _ReqData} ->
          {error, <<"Invalid Epoch stamp">>};
        Error ->
          Error
      end;
    Error ->
      Error
  end.    

encrypt_data(KeyInfo, RespData) ->
  ProRespData = create_pro_resp_data(<<>>, RespData),
  srpcryptor_lib:encrypt(KeyInfo, ProRespData).

decrypt_packet(KeyInfo, Packet) ->
  case srpcryptor_lib:decrypt(KeyInfo, Packet) of
    {ok, ProReqData} ->
      parse_pro_req_data(ProReqData);
    Error ->
      Error
  end.

%%====================================================================
%% Internal functions
%%====================================================================
info_for_key_id(KeyId) ->
  case srpcryptor_api_impl:get(lib_key, KeyId) of
    {ok, #{entityId := KeyId
          ,libKey   := LibKey
          ,hmacKey  := HmacKey}} ->
      {ok, {KeyId, LibKey, HmacKey}};
    {ok, _Map} ->
      {error, <<"Wrong EntityId for KeyId mapping">>};
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
