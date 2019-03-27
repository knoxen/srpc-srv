-module(srpc_srv).

-author("paul@knoxen.com").

-include ("srpc_srv.hrl").

%%==================================================================================================
%%
%% API exports
%%
%%==================================================================================================
-export([parse_packet/1,
         lib_exchange/2,
         srpc_action/2,
         unwrap/2,
         wrap/3
        ]).

%%==================================================================================================
%%
%%  SRPC Message Handling
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%%  Parse packet
%%--------------------------------------------------------------------------------------------------
-spec parse_packet(ReqData) -> Result when
    ReqData :: data_in(),
    Result  :: {lib_exchange, binary()} |
               {srpc_action, conn(), binary()} |
               {app_request, conn(), binary()} |
               invalid_msg() |
               error_msg().
%%--------------------------------------------------------------------------------------------------
parse_packet(<<16#00, Data/binary>>) ->
  {lib_exchange, Data};

parse_packet(<<16#10, Data/binary>>) ->
  packet_conn(srpc_action, Data);

parse_packet(<<16#ff, Data/binary>>) ->
  packet_conn(app_request, Data);

parse_packet(_) ->
  {error, <<"Invalid Srpc packet">>}.

%%--------------------------------------------------------------------------------------------------
%%  Packet conn info
%%--------------------------------------------------------------------------------------------------
-spec packet_conn(Type, Data) -> Result when
    Type   :: srpc_action | app_request,
    Data   :: binary(),
    Result :: {srpc_action, conn(), binary()} |
              {app_request, conn(), binary()} |
              invalid_msg().
%%--------------------------------------------------------------------------------------------------
packet_conn(Type, <<IdLen:8, Id:IdLen/binary, Data/binary>>) ->
  case conn(Id) of
    {ok, Conn} ->
      {Type, Conn, Data};

    Invalid ->
      Invalid
  end.

%%--------------------------------------------------------------------------------------------------
%%  SRPC actions
%%--------------------------------------------------------------------------------------------------
-spec srpc_action(Conn, Data) -> Result when
    Conn   :: conn(),
    Data   :: data_in(),
    Result :: {ActionAtom :: atom(), ok_binary() | error_msg() | invalid_msg()}.
%%--------------------------------------------------------------------------------------------------
srpc_action(#{conn_id := ConnId}, << 16#01:8, Data/binary>>) ->
  {lib_confirm, lib_confirm(ConnId, Data)};

srpc_action(#{conn_id := ConnId}, <<Action:8, Data/binary>>) ->
  case conn(ConnId) of
    {ok, Conn} ->
      srpc_action_route(Conn, Action, Data);

    Invalid ->
      Invalid
  end;

srpc_action(#{conn_id := _ConnId}, _) ->
  {undefined, {error, <<"Invalid Srpc action packet">>}};

srpc_action(_, _) ->
  {undefined, {error, <<"Connection info missing conn_id">>}}.

%%--------------------------------------------------------------------------------------------------
%%  Route SRPC actions
%%--------------------------------------------------------------------------------------------------
-spec srpc_action_route(Conn, Action, Data) -> Result when
    Conn   :: conn(),
    Action :: byte(),
    Data   :: binary(),
    Result :: {ActionAtom :: atom(), ok_binary() | error_msg() | invalid_msg()}.
%%--------------------------------------------------------------------------------------------------
srpc_action_route(Conn, 16#10, Data) -> {lib_user_exchange, user_exchange(Conn, Data, true)};

srpc_action_route(Conn, 16#11, Data) -> {lib_user_confirm, user_confirm(Conn, Data)};

srpc_action_route(Conn, 16#20, Data) -> {user_exchange, user_exchange(Conn, Data, false)};

srpc_action_route(Conn, 16#21, Data) -> {user_confirm, user_confirm(Conn, Data)};

srpc_action_route(Conn, 16#a0, Data) -> {registration, registration(Conn, Data)};

srpc_action_route(Conn, 16#b0, Data) -> {server_time, server_time(Conn, Data)};

srpc_action_route(Conn, 16#c0, Data) -> {refresh, refresh(Conn, Data)};

srpc_action_route(Conn, 16#ff, Data) -> {close, close(Conn, Data)};

srpc_action_route(_, _Action, _) -> {error, <<"Invalid srpc action">>}.

%%==================================================================================================
%%
%%  Lib Key Agreement
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%%  Lib Key Exchange
%%--------------------------------------------------------------------------------------------------
-spec lib_exchange(Config, ExchData) -> Result when
    Config   :: srpc_server_config(),
    ExchData :: data_in(),
    Result   :: {ok, binary()} | error_msg() | invalid_msg().
%%--------------------------------------------------------------------------------------------------
lib_exchange(Config, ExchReq) ->
  SrpcHandler = srpc_handler(),
  ConnId = SrpcHandler:conn_id(),
  case srpc_lib:process_lib_exchange_request(ConnId, Config, ExchReq) of
    {ok, {ExchConn, OptReqData}} ->
      OptRespData = case erlang:function_exported(SrpcHandler, lib_exchange_data, 1) of
                      true  -> SrpcHandler:lib_exchange_data(OptReqData);
                      false -> <<>>
                    end,

      case srpc_lib:create_lib_exchange_response(ExchConn, OptRespData) of
        {ok, {LibConn, ExchResp}} ->
          case SrpcHandler:put_exchange(ConnId, LibConn) of
            ok ->
              ConnIdLen = byte_size(ConnId),
              {ok, <<ConnIdLen:8, ConnId/binary, ExchResp/binary>>};
            Error ->
              Error
          end;

        Error ->
          Error
      end;

    {error, _} = Error ->
      Error;

    {invalid, _} = Invalid ->
      Invalid
  end.

%%--------------------------------------------------------------------------------------------------
%%   Lib Key Agreement Confirm
%%--------------------------------------------------------------------------------------------------
-spec lib_confirm(ConnId, ConfirmReq) -> Result when
    ConnId     :: id(),
    ConfirmReq :: binary(),
    Result     :: ok_binary() | error_msg() | invalid_msg().
%%--------------------------------------------------------------------------------------------------
lib_confirm(ConnId, ConfirmReq) ->
  SrpcHandler = srpc_handler(),
  case SrpcHandler:get_exchange(ConnId) of
    {ok, ExchConn} ->
      SrpcHandler:delete_exchange(ConnId),
      case srpc_lib:process_lib_confirm_request(ExchConn, ConfirmReq) of
        {ok, {ServerChallenge, SrpcReqData}} ->
          case parse_no_timing_data(SrpcReqData) of
            {ok, {Nonce, ConfirmReqData}} ->
              ConfirmRespData =
                case erlang:function_exported(SrpcHandler, lib_confirm_data, 1) of
                  true ->
                    SrpcHandler:lib_confirm_data(ConfirmReqData);
                  false ->
                    <<>>
                end,
              Time = system_time(),
              TimeRespData = <<Time:?SRPC_TIME_BITS, ConfirmRespData/binary>>,
              SrpcRespData = create_srpc_resp_data(Nonce, TimeRespData),
              {LibConn, ConfirmResp} =
                srpc_lib:create_lib_confirm_response(ExchConn, ServerChallenge, SrpcRespData),
              case SrpcHandler:put_conn(ConnId, LibConn) of
                ok ->
                  {ok, ConfirmResp};

                Error ->
                  Error
              end;

            Error ->
              Error
          end;

        Error ->
          Error
      end;

    undefined ->
      {invalid, <<"No exchange info for Client Id: ", ConnId/binary>>}
  end.

%%==================================================================================================
%%
%%  User Client Key Agreement
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%%   User Key Exchange
%%--------------------------------------------------------------------------------------------------
-spec user_exchange(Conn, ExchReq, Morph) -> Result when
    Conn    :: conn(),
    ExchReq :: binary(),
    Morph   :: boolean(),
    Result  :: ok_binary() | error_msg() | invalid_msg().
%%--------------------------------------------------------------------------------------------------
user_exchange(Conn, ExchReq, Morph) ->
  case srpc_lib:process_user_exchange_request(Conn, ExchReq) of
    {ok, {UserId, PublicKey, ReqData}} ->
      case parse_request_data(ReqData) of
        {ok, ParsedData} ->
          process_user_exchange(Conn, UserId, PublicKey, ParsedData, Morph);

        Invalid ->
          Invalid
      end;

    Error ->
      Error
  end.

%%--------------------------------------------------------------------------------------------------
%%
%%  Process user exchange
%%
%%--------------------------------------------------------------------------------------------------
%%    Exchange request
%%--------------------------------------------------------------------------------------------------
-spec process_user_exchange(Conn, UserId, PublicKey, ParsedData, Morph) -> Result when
    Conn       :: conn(),
    UserId     :: id(),
    PublicKey  :: srp_pub_key(),
    ParsedData :: {Nonce :: binary(), ExchData :: binary()},
    Morph      :: boolean(),
    Result     :: ok_binary() | error_msg() | invalid_msg().
%%--------------------------------------------------------------------------------------------------
process_user_exchange(Conn, UserId, PublicKey, {Nonce, ExchData}, Morph) ->
  SrpcHandler = srpc_handler(),
  RespData =
    case erlang:function_exported(SrpcHandler, user_exchange_data, 2) of
      true ->
        SrpcHandler:user_exchange_data(UserId, ExchData);
      false ->
        <<>>
    end,
  SrpcRespData = create_srpc_resp_data(Nonce, RespData),

  case SrpcHandler:get_registration(UserId) of
    {ok, Registration} ->
      create_user_exchange_response(Conn, Registration, PublicKey, SrpcRespData, Morph);

    undefined ->
      #{conn_id := UserConnId} = Conn,
      case srpc_lib:create_user_exchange_response(UserConnId, Conn, invalid,
                                                  PublicKey, SrpcRespData) of
        {ok, {_Conn, ExchResp}} ->
          {ok, ExchResp};

        Error ->
          Error
      end
  end.

%%--------------------------------------------------------------------------------------------------
%%    Exchange response
%%--------------------------------------------------------------------------------------------------
-spec create_user_exchange_response(ExchConn, SrpReg, PublicKey, RespData, Morph) -> Result when
    ExchConn  :: conn(),
    SrpReg    :: srp_registration() | invalid,
    PublicKey :: srp_pub_key(),
    RespData  :: binary(),
    Morph     :: boolean(),
    Result    :: ok_binary() | error_msg().
%%--------------------------------------------------------------------------------------------------
create_user_exchange_response(ExchConn, Registration, PublicKey, RespData, Morph) ->
  SrpcHandler = srpc_handler(),
  UserConnId = case Morph of
                 true ->
                   #{conn_id := ConnId} = ExchConn,
                   ConnId;
                 _ ->
                   SrpcHandler:conn_id()
               end,
  case srpc_lib:create_user_exchange_response(ExchConn, UserConnId, Registration,
                                              PublicKey, RespData) of
    {ok, {UserConn, ExchResp}} ->
      case SrpcHandler:put_exchange(UserConnId, UserConn) of
        ok ->
          {ok, ExchResp};

        Error ->
          Error
      end;

    Error ->
      Error
  end.


%%--------------------------------------------------------------------------------------------------
%%   User Key Confirm
%%--------------------------------------------------------------------------------------------------
-spec user_confirm(Conn, ConfirmReq) -> Result when
    Conn       :: conn(),
    ConfirmReq :: binary(),
    Result     :: ok_binary() | error_msg() | invalid_msg().
%%--------------------------------------------------------------------------------------------------
user_confirm(#{conn_id := ConnId} = CryptConn, ConfirmReq) ->
  case srpc_lib:process_user_confirm_request(CryptConn, ConfirmReq) of
    {ok, {UserConnId, ClientChallenge, ConfirmReqData}} ->
      SrpcHandler = srpc_handler(),
      case SrpcHandler:get_exchange(UserConnId) of
        {ok, UserExchConn} ->
          SrpcHandler:delete_exchange(UserConnId),
          case parse_request_data(ConfirmReqData) of
            {ok, {Nonce, OptReqData}} ->
              UserId = maps:get(entity_id, UserExchConn),
              OptRespData =
                case erlang:function_exported(SrpcHandler, user_confirm_data, 2) of
                  true ->
                    SrpcHandler:user_confirm_data(UserId, OptReqData);

                  false ->
                    <<>>
                end,
              ConfirmRespData = create_srpc_resp_data(Nonce, OptRespData),
              case srpc_lib:create_user_confirm_response(CryptConn, UserExchConn,
                                                         ClientChallenge,
                                                         ConfirmRespData) of
                {ok, UserConn, ConfirmResponse} ->
                  case SrpcHandler:put_conn(UserConnId, UserConn) of
                    ok ->
                      {ok, ConfirmResponse};

                    Error ->
                      Error
                  end;

                {invalid, _Conn, ConfirmResponse} ->
                  %% CxTBD Report invalid
                  {ok, ConfirmResponse}
              end;

            Invalid ->
              Invalid
          end;

        undefined ->
          {ok, create_dummy_response(CryptConn, ClientChallenge)}
      end;

    {invalid, DummyChallenge} ->
      {ok, create_dummy_response(CryptConn, DummyChallenge)};

    Error ->
      Error
  end.

create_dummy_response(Conn, Challenge) ->
  SrpcRespData = create_srpc_resp_data(<< 0:?SRPC_NONCE_BITS >>, <<>>),
  {_, _Conn, DummyResponse} =
    srpc_lib:create_user_confirm_response(Conn, invalid, Challenge, SrpcRespData),
  DummyResponse.

%% create_dummy_srpc_response_data(DataSize) ->
%% create_srpc_resp_data(<< 0:?SRPC_NONCE_BITS >>, << 0:(8*DataSize) >>).

%%==================================================================================================
%%
%%  Registration
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%%
%%--------------------------------------------------------------------------------------------------
-spec registration(Conn, RegReq) -> Result when
    Conn   :: conn(),
    RegReq :: binary(),
    Result :: ok_binary() | error_msg() | invalid_msg().
%%--------------------------------------------------------------------------------------------------
registration(Conn, RegReq) ->
  case srpc_lib:process_registration_request(Conn, RegReq) of
    {ok, {RegistrationCode, SrpcRegistrationData, SrpcReqData}} ->
      UserId = maps:get(user_id, SrpcRegistrationData),
      SrpcHandler = srpc_handler(),
      case parse_request_data(SrpcReqData) of
        {ok, {Nonce, RegRequestData}} ->
          RegResponseData =
            case erlang:function_exported(SrpcHandler, registration_data, 2) of
              true ->
                SrpcHandler:registration_data(UserId, RegRequestData);
              false ->
                <<>>
            end,
          SrpcRespData = create_srpc_resp_data(Nonce, RegResponseData),

          case RegistrationCode of
            ?SRPC_REGISTRATION_CREATE ->
              case SrpcHandler:get_registration(UserId) of
                undefined ->
                  case SrpcHandler:put_registration(UserId, SrpcRegistrationData) of
                    ok ->
                      srpc_lib:create_registration_response(Conn,
                                                            ?SRPC_REGISTRATION_OK,
                                                            SrpcRespData);
                    _Error ->
                      srpc_lib:create_registration_response(Conn,
                                                            ?SRPC_REGISTRATION_ERROR,
                                                            SrpcRespData)
                  end;
                {ok, _SrpcRegistrationData} ->
                  srpc_lib:create_registration_response(Conn,
                                                        ?SRPC_REGISTRATION_DUP,
                                                        SrpcRespData)
              end;
            ?SRPC_REGISTRATION_UPDATE ->
              case SrpcHandler:get_registration(UserId) of
                {ok, _PrevSrpcRegistrationData} ->
                  case SrpcHandler:put_registration(UserId, SrpcRegistrationData) of
                    ok ->
                      srpc_lib:create_registration_response(Conn,
                                                            ?SRPC_REGISTRATION_OK,
                                                            SrpcRespData);
                    _Error ->
                      srpc_lib:create_registration_response(Conn,
                                                            ?SRPC_REGISTRATION_ERROR,
                                                            SrpcRespData)
                  end;
                undefined ->
                  srpc_lib:create_registration_response(Conn,
                                                        ?SRPC_REGISTRATION_NONE,
                                                        SrpcRespData)
              end;
            _ ->
              srpc_lib:create_registration_response(Conn,
                                                    ?SRPC_REGISTRATION_ERROR,
                                                    SrpcRespData)
          end;
        Invalid ->
          Invalid
      end;
    Error ->
      Error
  end.

%%==================================================================================================
%%
%% Server Time
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
-spec server_time(Conn, TimeReq) -> Result when
    Conn    :: conn(),
    TimeReq :: binary(),
    Result  :: ok_binary() | error_msg() | invalid_msg().
%%--------------------------------------------------------------------------------------------------
server_time(Conn, TimeReq) ->
  %% To bypass req age check (which needs an estimate of server time), don't use srpc_srv:unwrap
  case srpc_lib:decrypt(requester, Conn, TimeReq) of
    {ok, ReqData} ->
      case parse_no_timing_data(ReqData) of
        {ok, {Nonce, Data}} ->
          Time = system_time(),
          wrap(Conn, Nonce, <<Time:?SRPC_TIME_BITS, Data/binary>>);

        Error ->
          Error
      end;

    Error ->
      Error
  end.

%%==================================================================================================
%%
%% Refresh Srpc Keys
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
-spec refresh(Conn, RefreshReq) -> Result when
    Conn       :: conn(),
    RefreshReq :: binary(),
    Result     :: ok_binary() | error_msg() | invalid_msg().
%%--------------------------------------------------------------------------------------------------
refresh(#{conn_id := ConnId,
          keys := #{}
         } = OldConn,
        RefreshReq) ->
  case unwrap(OldConn, RefreshReq) of
    {ok, {Nonce, Data}} ->
      case srpc_lib:refresh_keys(OldConn, Data) of
        {ok, FreshConn} ->
          SrpcHandler = srpc_handler(),
          case SrpcHandler:put_conn(ConnId, FreshConn) of
            ok ->
              wrap(FreshConn, Nonce, Data);

            Error ->
              Error
          end;

        Error ->
          Error
      end;

    Error ->
      Error
  end.

%%==================================================================================================
%%
%% Client Close
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
-spec close(Conn, CloseReq) -> Result when
    Conn     :: conn(),
    CloseReq :: binary(),
    Result   :: ok_binary() | error_msg() | invalid_msg().
%%--------------------------------------------------------------------------------------------------
close(#{conn_id := ConnId} = Conn, CloseReq) ->
  case unwrap(Conn, CloseReq) of
    {ok, {Nonce, Data}} ->
      SrpcHandler = srpc_handler(),
      SrpcHandler:delete_conn(ConnId),
      wrap(Conn, Nonce, Data);

    Error ->
      Error
  end.

%%==================================================================================================
%%
%%  Connection
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
-spec conn(ConnId) -> Result when
    ConnId :: id(),
    Result :: ok_conn() | invalid_msg().
%%--------------------------------------------------------------------------------------------------
conn(ConnId) ->
  SrpcHandler = srpc_handler(),
  case SrpcHandler:get_conn(ConnId) of
    undefined ->
      case SrpcHandler:get_exchange(ConnId) of
        undefined ->
          {invalid, <<"Invalid ConnId: ", ConnId/binary>>};

        Result ->
          Result
      end;

    Result ->
      Result
  end.

%%==================================================================================================
%%
%%  Unwrap / Wrap
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%%  Unwrap data
%%--------------------------------------------------------------------------------------------------
-spec unwrap(Conn, Data) -> Result when
    Conn   :: conn(),
    Data   :: binary(),
    Result :: nonced_data() | invalid_msg().
%%--------------------------------------------------------------------------------------------------
unwrap(Conn, Data) ->
  case srpc_lib:decrypt(requester, Conn, Data) of
    {ok, SrpcData} ->
      parse_request_data(SrpcData);
    Invalid ->
      Invalid
  end.

%%--------------------------------------------------------------------------------------------------
%%  Wrap data
%%--------------------------------------------------------------------------------------------------
-spec wrap(Conn, Nonce, Data) -> Result when
    Conn   :: conn(),
    Nonce  :: binary(),
    Data   :: binary(),
    Result :: ok_binary().
%%--------------------------------------------------------------------------------------------------
wrap(Conn, Nonce, Data) ->
  SrpcData = create_srpc_resp_data(Nonce, Data),
  {ok, srpc_lib:encrypt(responder, Conn, SrpcData)}.

%%==================================================================================================
%%
%% Private functions
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%%  Parse nonce and data while ignoring request time
%%--------------------------------------------------------------------------------------------------
-spec parse_no_timing_data(Data) -> Result when
    Data   :: binary(),
    Result :: nonced_data() | error_msg().
%%--------------------------------------------------------------------------------------------------

parse_no_timing_data(<<?SRPC_HDR_VSN:?SRPC_HDR_BITS, _RequestTime:?SRPC_TIME_BITS,
                       NonceLen:?SRPC_NONCE_BITS, Nonce:NonceLen/binary,
                       Data/binary>>) ->
  {ok, {Nonce, Data}};

parse_no_timing_data(_) ->
  {error, <<"Invalid lib confirm packet">>}.

%%------------------------------------------------------------------------------------------------
%%  Parse incoming request data
%%------------------------------------------------------------------------------------------------
-spec parse_request_data(Data) -> Result when
    Data   :: binary(),
    Result :: nonced_data() | invalid_msg().
%%------------------------------------------------------------------------------------------------
parse_request_data(<<?SRPC_HDR_VSN:?SRPC_HDR_BITS, ReqTime:?SRPC_TIME_BITS,
                     NonceLen:?SRPC_NONCE_BITS, Nonce:NonceLen/binary,
                     ReqData/binary>>) ->
  OkResponse = {ok, {Nonce, ReqData}},
  SrpcHandler = srpc_handler(),
  case erlang:function_exported(SrpcHandler, req_age_tolerance, 0) of
    false ->
      OkResponse;
    true ->
      case SrpcHandler:req_age_tolerance() of
        Tolerance when 0 < Tolerance ->
          SysTime = system_time(),
          ReqAge = abs(SysTime - ReqTime),
          case ReqAge =< Tolerance of
            true ->
              case erlang:byte_size(Nonce) of
                0 ->
                  OkResponse;
                _ ->
                  case erlang:function_exported(SrpcHandler, nonce, 1) of
                    true ->
                      case SrpcHandler:nonce(Nonce) of
                        true ->
                          OkResponse;
                        false ->
                          {invalid, <<"Repeat nonce: ", Nonce/binary>>}
                      end;
                    false ->
                      OkResponse
                  end
              end;
            false ->
              Age = erlang:list_to_binary(io_lib:format("~B", [ReqAge])),
              {invalid, <<"Request age: ", Age/binary>>}
          end;
        _ ->
          OkResponse
      end
  end;

parse_request_data(<<_:?SRPC_HDR_BITS, _Rest/binary>>) ->
  {error, <<"Invalid Srpc header version number">>};

parse_request_data(_ReqData) ->
  {error, <<"Invalid Srpc request data">>}.

%%--------------------------------------------------------------------------------------------------
%%  Create SRPC formated response data
%%--------------------------------------------------------------------------------------------------
-spec create_srpc_resp_data(Nonce, Data) -> Result when
    Nonce  :: binary(),
    Data   :: binary(),
    Result :: binary().
%%--------------------------------------------------------------------------------------------------
create_srpc_resp_data(Nonce, Data) ->
  NonceLen = erlang:byte_size(Nonce),
  Time = system_time(),
  <<?SRPC_HDR_VSN:?SRPC_HDR_BITS, Time:?SRPC_TIME_BITS, NonceLen:?SRPC_NONCE_BITS, Nonce/binary, Data/binary>>.

%%--------------------------------------------------------------------------------------------------
%%  System time
%%--------------------------------------------------------------------------------------------------
-spec system_time() -> integer().
%%--------------------------------------------------------------------------------------------------
system_time() ->
  erlang:system_time(second).

%%--------------------------------------------------------------------------------------------------
%%  Srpc Handler
%%--------------------------------------------------------------------------------------------------
-spec srpc_handler() -> module().
%%--------------------------------------------------------------------------------------------------
srpc_handler() ->
  case application:get_env(srpc_srv, srpc_handler) of
    {ok, SrpcHandler} ->
      SrpcHandler;
    _ ->
      erlang:error("Missing srpc_srv configuration for srpc_handler")
  end.
