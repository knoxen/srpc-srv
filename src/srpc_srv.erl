-module(srpc_srv).

-author("paul@knoxen.com").

-include ("srpc_srv.hrl").

%%==================================================================================================
%%
%% API exports
%%
%%==================================================================================================
-export([parse_packet/1,
         lib_exchange/1,
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
               {srpc_action, conn_info(), binary()} |
               {app_request, conn_info(), binary()} |
               invalid_msg() |
               error_msg().
%%--------------------------------------------------------------------------------------------------
parse_packet(<<16#00, Data/binary>>) ->
  {lib_exchange, Data};
parse_packet(<<16#10, Data/binary>>) ->
  packet_conn_info(srpc_action, Data);
parse_packet(<<16#ff, Data/binary>>) ->
  packet_conn_info(app_request, Data);
parse_packet(_) ->
  {error, <<"Invalid SRPC packet">>}.

%%--------------------------------------------------------------------------------------------------
%%  Packet conn info
%%--------------------------------------------------------------------------------------------------
-spec packet_conn_info(Type, Data) -> Result when
    Type   :: srpc_action | app_request,
    Data   :: binary(),
    Result :: {srpc_action, conn_info(), binary()} |
              {app_request, conn_info(), binary()} |
              invalid_msg().
%%--------------------------------------------------------------------------------------------------
packet_conn_info(Type, <<IdLen:8, Id:IdLen/binary, Data/binary>>) ->
  case conn_info(Id) of
    {ok, ConnInfo} ->
      {Type, ConnInfo, Data};
    Invalid ->
      Invalid
  end.

%%--------------------------------------------------------------------------------------------------
%%  SRPC actions
%%--------------------------------------------------------------------------------------------------
-spec srpc_action(ConnInfo, Data) -> Result when
    ConnInfo    :: conn_info(),
    Data        :: data_in(),
    Result      :: {atom(), ok_response() | error_msg() | invalid_msg()}.
%%--------------------------------------------------------------------------------------------------
srpc_action(#{conn_id := ConnId}, <<SrpcCode:8, ActionData/binary>>) ->
  srpc_route(SrpcCode, {ConnId, ActionData});

srpc_action(#{conn_id := _ConnId}, _) ->
  {undefined, {error, <<"Invalid srpc action packet">>}};

srpc_action(_, _) ->
  {undefined, {error, <<"Connection info missing conn_id">>}}.

%%--------------------------------------------------------------------------------------------------
%%  Route SRPC actions
%%--------------------------------------------------------------------------------------------------
-spec srpc_route(Byte, ActionTerm) -> Result when
    Byte       :: byte(),
    ActionTerm :: {conn_id(), binary(), any()},
    Result     :: {atom(), ok_response() | error_msg() | invalid_msg()}.
%%--------------------------------------------------------------------------------------------------
srpc_route(16#01, ActionTerm) -> {lib_confirm, lib_confirm(ActionTerm)};

srpc_route(16#10, ActionTerm) -> {lib_user_exchange, user_exchange(ActionTerm, true)};

srpc_route(16#11, ActionTerm) -> {lib_user_confirm, user_confirm(ActionTerm)};

srpc_route(16#20, ActionTerm) -> {user_exchange, user_exchange(ActionTerm, false)};

srpc_route(16#21, ActionTerm) -> {user_confirm, user_confirm(ActionTerm)};

srpc_route(16#a0, ActionTerm) -> {registration, registration(ActionTerm)};

srpc_route(16#b0, ActionTerm) -> {server_time, server_time(ActionTerm)};

srpc_route(16#c0, ActionTerm) -> {refresh, refresh(ActionTerm)};

srpc_route(16#ff, ActionTerm) -> {close, close(ActionTerm)};

srpc_route(_, __ActionTerm)   -> {error, <<"Invalid srpc action">>}.

%%==================================================================================================
%%
%%  Lib Client Key Agreement
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%%  Lib key exchange
%%    
%%
%%--------------------------------------------------------------------------------------------------
-spec lib_exchange(ExchangeData) -> Result when
    ExchangeData :: data_in(),
    Result       :: {ok, binary()} | error_msg() | invalid_msg().
%%--------------------------------------------------------------------------------------------------
lib_exchange(ExchangeData) ->
  case srpc_lib:process_lib_key_exchange_request(ExchangeData) of
    {ok, {ClientPublicKey, OptReqData}} ->
      SrpcHandler = srpc_handler(),
      ConnId = SrpcHandler:conn_id(),
      ConnInfo = #{conn_type       => lib
                  ,entity_id       => srpc_lib:srpc_id()
                  ,conn_id         => ConnId
                  ,exch_public_key => ClientPublicKey},
      OptRespData = case erlang:function_exported(SrpcHandler, lib_exchange_data, 1) of
                      true  -> SrpcHandler:lib_exchange_data(OptReqData);
                      false -> <<>>
                    end,
      case srpc_lib:create_lib_key_exchange_response(ConnInfo, OptRespData) of
        {ok, {ConnInfo2, ExchangeResponse}} ->
          case SrpcHandler:put_exchange(ConnId, ConnInfo2) of
            ok ->
              ConnIdLen = byte_size(ConnId),
              {ok, <<ConnIdLen:8, ConnId/binary, ExchangeResponse/binary>>};
            Error ->
              Error
          end;
        Error ->
          Error
      end;
    Invalid ->
      Invalid
  end.

%%--------------------------------------------------------------------------------------------------
%%   Lib Key Agreement Confirm
%%--------------------------------------------------------------------------------------------------
-spec lib_confirm({ConnId, Request}) -> Result when
    ConnId  :: conn_id(),
    Request :: binary(),
    Result  :: ok_response() | error_msg() | invalid_msg().
%%--------------------------------------------------------------------------------------------------
lib_confirm({ConnId, ConfirmRequest}) ->
  %% io:format("~p:lib_confirm~n ConfirmRequest=~p~n",
  %%           [?MODULE, srpc_util:bin_to_hex(ConfirmRequest)]),
  SrpcHandler = srpc_handler(),
  case SrpcHandler:get_exchange(ConnId) of
    {ok, ExchConnInfo} ->
      SrpcHandler:delete_exchange(ConnId),
      case srpc_lib:process_lib_key_confirm_request(ExchConnInfo, ConfirmRequest) of
        {ok, {ServerChallenge, SrpcReqData}} ->
          %% io:format("~p:lib_confirm~n", [?MODULE]),
          %% io:format(" ServerChallenge=~p~n", [srpc_util:bin_to_hex(ServerChallenge)]),
          %% io:format(" SrpcReqData=~p~n", [srpc_util:bin_to_hex(SrpcReqData)]),
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
              TimeRespData = <<Time:?TIME_BITS, ConfirmRespData/binary>>,
              SrpcRespData = create_srpc_resp_data(Nonce, TimeRespData),
              case srpc_lib:create_lib_key_confirm_response(ExchConnInfo, ServerChallenge,
                                                            SrpcRespData) of
                {ok, ConnInfo, ConfirmResponse} ->
                  case SrpcHandler:put_conn(ConnId, ConnInfo) of
                    ok ->
                      {ok, ConfirmResponse};
                    Error ->
                      Error
                  end;
                {invalid, ConfirmResponse} ->
                  {ok, ConfirmResponse};
                Error ->
                  Error
              end;
            Error ->
              Error
          end;
        Error ->
          io:format("Error=~p~n", [Error]),
          Error
      end;
    undefined ->
      {invalid, <<"No exchange info for Client Id: ", ConnId/binary>>}
  end.

%%==================================================================================================
%%
%% User Client Key Agreement
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%%   User Key Exchange
%%--------------------------------------------------------------------------------------------------
-spec user_exchange({ConnId, Request}, Morph) -> Result when
    ConnId   :: conn_id(),
    Request     :: binary(),
    Morph       :: boolean(),
    Result      :: ok_response() | error_msg() | invalid_msg().
%%--------------------------------------------------------------------------------------------------
user_exchange({ConnId, ExchangeData}, Morph) ->
  case conn_info(ConnId) of
    {ok, ConnInfo} ->
      case srpc_lib:process_user_key_exchange_request(ConnInfo, ExchangeData) of
        {ok, ExchangeTerm} ->
          user_key_exchange_request(ConnId, ConnInfo, ExchangeTerm, Morph);
        Error ->
          Error
      end;
    Invalid ->
      Invalid
  end.

%%--------------------------------------------------------------------------------------------------
%%   User Key Confirm
%%--------------------------------------------------------------------------------------------------
-spec user_confirm({ConnId, Request}) -> Result when
    ConnId      :: conn_id(),
    Request     :: binary(),
    Result      :: ok_response() | error_msg() | invalid_msg().
%%--------------------------------------------------------------------------------------------------
user_confirm({ConnId, ConfirmRequest}) ->
  case conn_info(ConnId) of
    {ok, CryptConnInfo} ->
      case srpc_lib:process_user_key_confirm_request(CryptConnInfo, ConfirmRequest) of
        {ok, {ClientChallenge, SrpcReqConfirmData}} ->
          SrpcHandler = srpc_handler(),
          case SrpcHandler:get_exchange(ConnId) of
            {ok, ExchConnInfo} ->
              SrpcHandler:delete_exchange(ConnId),
              case parse_request_data(SrpcReqConfirmData) of
                {ok, {Nonce, ReqConfirmData}} ->
                  UserId = maps:get(entity_id, ExchConnInfo),
                  RespConfirmData =
                    case erlang:function_exported(SrpcHandler, user_confirm_data, 2) of
                      true ->
                        SrpcHandler:user_confirm_data(UserId, ReqConfirmData);
                      false ->
                        <<>>
                    end,
                  SrpcRespData = create_srpc_resp_data(Nonce, RespConfirmData),
                  case srpc_lib:create_user_key_confirm_response(CryptConnInfo, ExchConnInfo,
                                                                 ClientChallenge,
                                                                 SrpcRespData) of
                    {ok, ConnInfo, ConfirmResponse} ->
                      ConnInfo2 = maps:put(conn_id, ConnId, ConnInfo),
                      case SrpcHandler:put_conn(ConnId, ConnInfo2) of
                        ok ->
                          {ok, ConfirmResponse};
                        Error ->
                          Error
                      end;
                    {invalid, _ConnInfo, ConfirmResponse} ->
                      %% CxTBD Report invalid
                      {ok, ConfirmResponse}
                  end;
                Invalid ->
                  Invalid
              end;
            undefined ->
              Nonce = crypto:strong_rand_bytes(erlang:trunc(?NONCE_BITS/8)),
              SrpcRespData = create_srpc_resp_data(Nonce, <<>>),
              {_, _ConnInfo, ConfirmResponse} =
                srpc_lib:create_user_key_confirm_response(CryptConnInfo, invalid,
                                                          ClientChallenge, SrpcRespData),
              {ok, ConfirmResponse}
          end;
        Error ->
          Error
      end;
    Invalid ->
      Invalid
  end.

%%==================================================================================================
%%
%%  Registration
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%%  
%%--------------------------------------------------------------------------------------------------
-spec registration({ConnId, Request}) -> Result when
    ConnId    :: conn_id(),
    Request     :: binary(),
    Result      :: ok_response() | error_msg() | invalid_msg().
%%--------------------------------------------------------------------------------------------------
registration({ConnId, RegistrationRequest}) ->
  case conn_info(ConnId) of
    {ok, ConnInfo} ->
      case srpc_lib:process_registration_request(ConnInfo, RegistrationRequest) of
        {ok, {RegistrationCode, SrpcRegistrationData, SrpcReqData}} ->
          UserId = maps:get(user_id, SrpcRegistrationData),
          SrpcHandler = srpc_handler(),
          case parse_request_data(SrpcReqData) of
            {ok, {Nonce, ReqRegistrationData}} ->
              RespRegistrationData =
                case erlang:function_exported(SrpcHandler, registration_data, 2) of
                  true ->
                    SrpcHandler:registration_data(UserId, ReqRegistrationData);
                  false ->
                    <<>>
                end,
              SrpcRespData = create_srpc_resp_data(Nonce, RespRegistrationData),

              case RegistrationCode of
                ?SRPC_REGISTRATION_CREATE ->
                  case SrpcHandler:get_registration(UserId) of
                    undefined ->
                      case SrpcHandler:put_registration(UserId, SrpcRegistrationData) of
                        ok ->
                          srpc_lib:create_registration_response(ConnInfo,
                                                                ?SRPC_REGISTRATION_OK,
                                                                SrpcRespData);
                        _Error ->
                          srpc_lib:create_registration_response(ConnInfo,
                                                                ?SRPC_REGISTRATION_ERROR,
                                                                SrpcRespData)
                      end;
                    {ok, _SrpcRegistrationData} ->
                      srpc_lib:create_registration_response(ConnInfo,
                                                            ?SRPC_REGISTRATION_DUP,
                                                            SrpcRespData)
                  end;
                ?SRPC_REGISTRATION_UPDATE ->
                  case SrpcHandler:get_registration(UserId) of
                    {ok, _PrevSrpcRegistrationData} ->
                      case SrpcHandler:put_registration(UserId, SrpcRegistrationData) of
                        ok ->
                          srpc_lib:create_registration_response(ConnInfo,
                                                                ?SRPC_REGISTRATION_OK,
                                                                SrpcRespData);
                        _Error ->
                          srpc_lib:create_registration_response(ConnInfo,
                                                                ?SRPC_REGISTRATION_ERROR,
                                                                SrpcRespData)
                      end;
                    undefined ->
                      srpc_lib:create_registration_response(ConnInfo,
                                                            ?SRPC_REGISTRATION_NOT_FOUND,
                                                            SrpcRespData)
                  end;
                _ ->
                  srpc_lib:create_registration_response(ConnInfo,
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

%%==================================================================================================
%%
%% Server Time
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
-spec server_time({ConnId, Request}) -> Result when
    ConnId  :: conn_id(),
    Request :: binary(),
    Result  :: ok_response() | error_msg() | invalid_msg().
%%--------------------------------------------------------------------------------------------------
server_time({ConnId, ServerTimeRequest}) ->
  case conn_info(ConnId) of
    {ok, ConnInfo} ->
      %% To bypass req age check (which needs an estimate of server time), don't use srpc_srv:unwrap
      case srpc_lib:decrypt(origin_requester, ConnInfo, ServerTimeRequest) of
        {ok, ReqData} ->
          case parse_no_timing_data(ReqData) of
            {ok, {Nonce, Data}} ->
              Time = system_time(),
              TimeRespData = <<Time:?TIME_BITS, Data/binary>>,
              wrap(ConnInfo, Nonce, TimeRespData);
            Error ->
              Error
          end;
        Error ->
          Error
      end;
    Invalid ->
      Invalid
  end.

%%==================================================================================================
%%
%% Refresh Srpc Keys
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
-spec refresh({ConnId, Request}) -> Result when
    ConnId  :: conn_id(),
    Request :: binary(),
    Result  :: ok_response() | error_msg() | invalid_msg().
%%--------------------------------------------------------------------------------------------------
refresh({ConnId, Request}) ->
  case conn_info(ConnId) of
    {ok, ConnInfo} ->
      case unwrap(ConnInfo, Request) of
        {ok, {Nonce, Salt}} ->
          NewConnInfo = srpc_lib:refresh_keys(ConnInfo, Salt),
          SrpcHandler = srpc_handler(),
          case SrpcHandler:put_conn(ConnId, NewConnInfo) of
            ok ->
              wrap(NewConnInfo, Nonce, Salt);
            Error ->
              Error
          end;
        Error ->
          Error
      end;
    Invalid ->
      Invalid
  end.

%%==================================================================================================
%%
%% Client Close
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
-spec close({ConnId, Request}) -> Result when
    ConnId    :: conn_id(),
    Request     :: binary(),
    Result      :: ok_response() | error_msg() | invalid_msg().
%%--------------------------------------------------------------------------------------------------
close({ConnId, CloseRequest}) ->
  case conn_info(ConnId) of
    {ok, ConnInfo} ->
      case unwrap(ConnInfo, CloseRequest) of
        {ok, {Nonce, Data}} ->
          SrpcHandler = srpc_handler(),
          SrpcHandler:delete_conn(ConnId),
          wrap(ConnInfo, Nonce, Data);
        Error ->
          Error
      end;
    Invalid ->
      Invalid
  end.

%%==================================================================================================
%%
%%  Client info map
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
-spec conn_info(ConnId) -> Result when
    ConnId :: conn_id(),
    Result :: {ok, conn_info()} | invalid_msg().
%%--------------------------------------------------------------------------------------------------
conn_info(ConnId) ->
  SrpcHandler = srpc_handler(),
  case SrpcHandler:get_exchange(ConnId) of
    undefined ->
      case SrpcHandler:get_conn(ConnId) of
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
-spec unwrap(ConnInfo, Data) -> Result when
    ConnInfo :: conn_info(),
    Data     :: binary(),
    Result   :: nonced_data() | invalid_msg().
%%--------------------------------------------------------------------------------------------------
unwrap(ConnInfo, Data) ->
  case srpc_lib:decrypt(origin_requester, ConnInfo, Data) of
    {ok, SrpcData} ->
      parse_request_data(SrpcData);
    Invalid ->
      Invalid
  end.

%%--------------------------------------------------------------------------------------------------
%%  Wrap data
%%--------------------------------------------------------------------------------------------------
-spec wrap(ConnInfo, Nonce, Data) -> Result when
    ConnInfo :: conn_info(),
    Nonce    :: binary(),
    Data     :: binary(),
    Result   :: binary() | error_msg().
%%--------------------------------------------------------------------------------------------------
wrap(ConnInfo, Nonce, Data) ->
  SrpcData = create_srpc_resp_data(Nonce, Data),
  srpc_lib:encrypt(origin_responder, ConnInfo, SrpcData).

%%==================================================================================================
%%
%% Private functions
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%%  User key exchange request
%%--------------------------------------------------------------------------------------------------
-spec user_key_exchange_request(ConnId, ConnInfo, {UserId, PublicKey, RequestData}, Morph)
                               -> Result when
    ConnId      :: conn_id(),
    ConnInfo    :: conn_info(),
    UserId      :: user_id(),
    PublicKey   :: exch_key(),
    RequestData :: binary(),
    Morph       :: boolean(),
    Result      :: ok_response() | error_msg() | invalid_msg().
%%--------------------------------------------------------------------------------------------------
user_key_exchange_request(ConnId, ConnInfo, {UserId, PublicKey, RequestData}, Morph) ->
  case parse_request_data(RequestData) of
    {ok, {Nonce, ReqExchangeData}} ->
      SrpcHandler = srpc_handler(),
      RespData =
        case erlang:function_exported(SrpcHandler, user_exchange_data, 2) of
          true ->
            SrpcHandler:user_exchange_data(UserId, ReqExchangeData);
          false ->
            <<>>
        end,
      SrpcRespData = create_srpc_resp_data(Nonce, RespData),
      case SrpcHandler:get_registration(UserId) of
        {ok, Registration} ->
          user_key_exchange_response(ConnId, ConnInfo, Registration, PublicKey, RespData, Morph);
        undefined ->
          srpc_lib:create_user_key_exchange_response(ConnId, ConnInfo, invalid, PublicKey, 
                                                     SrpcRespData)
      end;
    Invalid ->
      Invalid
  end.

%%--------------------------------------------------------------------------------------------------
%%  User key exchange response
%%--------------------------------------------------------------------------------------------------
-spec user_key_exchange_response(ConnId, ConnInfo, Registration, PublicKey, RespData, Morph)
                                -> Result when
    ConnId       :: conn_id(),
    ConnInfo     :: conn_info(),
    Registration :: registration(),
    PublicKey    :: exch_key(),
    RespData     :: binary(),
    Morph        :: boolean(),
    Result       :: ok_response() | error_msg().
%%--------------------------------------------------------------------------------------------------
user_key_exchange_response(ConnId, ConnInfo, Registration, PublicKey, RespData, Morph) ->
  SrpcHandler = srpc_handler(),
  UserConnId =
    case Morph of
      true ->
        ConnId;
      _ ->
        SrpcHandler:conn_id()
    end,
  case srpc_lib:create_user_key_exchange_response(UserConnId, ConnInfo, Registration,
                                                  PublicKey, RespData) of
    {ok, {ExchConnInfo, ExchangeResponse}} ->
      UserConnInfo = maps:put(conn_id, UserConnId, ExchConnInfo),
      case SrpcHandler:put_exchange(UserConnId, UserConnInfo) of
        ok ->
          {ok, ExchangeResponse};
        Error ->
          Error
      end;
    Error ->
      Error
  end.

%%--------------------------------------------------------------------------------------------------
%%  Parse nonce and data while ignoring request time
%%--------------------------------------------------------------------------------------------------
-spec parse_no_timing_data(Data) -> Result when
    Data   :: binary(),
    Result :: nonced_data() | error_msg().
%%--------------------------------------------------------------------------------------------------

parse_no_timing_data(<<?HDR_VSN:?HDR_BITS, _RequestTime:?TIME_BITS,
                    NonceLen:?NONCE_BITS, Nonce:NonceLen/binary,
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
parse_request_data(<<?HDR_VSN:?HDR_BITS, ReqTime:?TIME_BITS, 
                   NonceLen:?NONCE_BITS, Nonce:NonceLen/binary,
                   ReqData/binary>>) ->
  OKResponse = {ok, {Nonce, ReqData}},
  SrpcHandler = srpc_handler(),
  case erlang:function_exported(SrpcHandler, req_age_tolerance, 0) of
    false ->
      OKResponse;
    true ->
      case SrpcHandler:req_age_tolerance() of
        Tolerance when 0 < Tolerance ->
          SysTime = system_time(),
          ReqAge = abs(SysTime - ReqTime),
          case ReqAge =< Tolerance of
            true ->
              case erlang:byte_size(Nonce) of
                0 ->
                  OKResponse;
                _ ->
                  case erlang:function_exported(SrpcHandler, nonce, 1) of
                    true ->
                      case SrpcHandler:nonce(Nonce) of
                        true ->
                          OKResponse;
                        false ->
                          {invalid, <<"Repeat nonce: ", Nonce/binary>>}
                      end;
                    false ->
                      OKResponse
                  end
              end;
            false ->
              Age = erlang:list_to_binary(io_lib:format("~B", [ReqAge])),
              {invalid, <<"Request age: ", Age/binary>>}
          end;
        _ ->
          OKResponse
      end
  end;

parse_request_data(<<_:?HDR_BITS, _Rest/binary>>) ->
  {error, <<"Invalid SRPC header version number">>};

parse_request_data(_ReqData) ->
  {error, <<"Invalid SRPC request data">>}.

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
  <<?HDR_VSN:?HDR_BITS, Time:?TIME_BITS, NonceLen:?NONCE_BITS, Nonce/binary, Data/binary>>.

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
      throw("Application srpc_srv missing env setting for srpc_handler")
  end.
