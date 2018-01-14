-module(srpc_srv).

-author("paul@knoxen.com").

-include ("srpc_srv.hrl").

%%==================================================================================================
%%
%% API exports
%%
%%==================================================================================================
-export([parse_packet/2
        ,lib_exchange/2
        ,srpc_action/3
        ,unwrap/3
        ,wrap/3
        ]).

%%==================================================================================================
%%
%%  SRPC Message Handling
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%%  Parse packet
%%--------------------------------------------------------------------------------------------------
-spec parse_packet(ReqData, SrpcHandler) -> Result when
    ReqData     :: data_in(),
    SrpcHandler :: module(),
    Result      :: {lib_exchange, binary()} |
                   {srpc_action, conn_info(), binary()} |
                   {app_request, conn_info(), binary()} |
                   invalid_msg() |
                   error_msg().
%%--------------------------------------------------------------------------------------------------
parse_packet(<<16#00, Data/binary>>, _SrpcHandler) ->
  {lib_exchange, Data};
parse_packet(<<16#10, Data/binary>>, SrpcHandler) ->
  packet_conn_info(srpc_action, Data, SrpcHandler);
parse_packet(<<16#ff, Data/binary>>, SrpcHandler) ->
  packet_conn_info(app_request, Data, SrpcHandler);
parse_packet(_, _SrpcHandler) ->
  {error, <<"Invalid SRPC packet">>}.

%%--------------------------------------------------------------------------------------------------
%%  Packet conn info
%%--------------------------------------------------------------------------------------------------
-spec packet_conn_info(Type, Data, SrpcHandler) -> Result when
    Type        :: srpc_action | app_request,
    Data        :: binary(),
    SrpcHandler :: module(),
    Result      :: {srpc_action, conn_info(), binary()} |
                   {app_request, conn_info(), binary()} |
                   invalid_msg().
%%--------------------------------------------------------------------------------------------------
packet_conn_info(Type, <<IdLen:8, Id:IdLen/binary, Data/binary>>, SrpcHandler) ->
  case conn_info(Id, SrpcHandler) of
    {ok, ConnInfo} ->
      {Type, ConnInfo, Data};
    Invalid ->
      Invalid
  end.
  
%%--------------------------------------------------------------------------------------------------
%%  SRPC actions
%%--------------------------------------------------------------------------------------------------
-spec srpc_action(ConnInfo, Data, SrpcHandler) -> Result when
    ConnInfo    :: conn_info(),
    Data        :: data_in(),
    SrpcHandler :: module(),
    Result      :: {atom(), ok_response() | error_msg() | invalid_msg()}.
%%--------------------------------------------------------------------------------------------------
srpc_action(#{conn_id := ConnId}, <<SrpcCode:8, ActionData/binary>>, SrpcHandler) ->
  srpc_route(SrpcCode, {ConnId, ActionData, SrpcHandler});

srpc_action(#{conn_id := _ConnId}, _, _) ->
  {undefined, {error, <<"Invalid srpc action packet">>}};

srpc_action(_, _, _) ->
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
%%--------------------------------------------------------------------------------------------------
-spec lib_exchange(ExchangeData, SrpcHandler) -> Result when
    ExchangeData :: data_in(),
    SrpcHandler  :: module(),
    Result       :: {ok, binary()} | error_msg() | invalid_msg().
%%--------------------------------------------------------------------------------------------------
lib_exchange(ExchangeData, SrpcHandler) ->
  case srpc_lib:lib_key_process_exchange_request(ExchangeData) of
    {ok, {ClientPublicKey, ReqData}} ->
      RespData =
        case erlang:function_exported(SrpcHandler, lib_exchange_data, 1) of
          true ->
            SrpcHandler:lib_exchange_data(ReqData);
          false ->
            <<>>
        end,
      ConnId = SrpcHandler:conn_id(),
      case srpc_lib:lib_key_create_exchange_response(ConnId, ClientPublicKey, RespData) of
        {ok, {ExchangeMap, ExchangeResponse}} ->
          ConnId = maps:get(conn_id, ExchangeMap),
          case SrpcHandler:put_exchange(ConnId, ExchangeMap) of
            ok ->
              {ok, ExchangeResponse};
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
-spec lib_confirm({ConnId, Request, SrpcHandler}) -> Result when
    ConnId    :: conn_id(),
    Request     :: binary(),
    SrpcHandler :: module(),
    Result      :: ok_response() | error_msg() | invalid_msg().
%%--------------------------------------------------------------------------------------------------
lib_confirm({ConnId, ConfirmRequest, SrpcHandler}) ->
  case SrpcHandler:get_exchange(ConnId) of
    {ok, ExchConnInfo} ->
      SrpcHandler:delete_exchange(ConnId),
      case srpc_lib:lib_key_process_confirm_request(ExchConnInfo, ConfirmRequest) of
        {ok, {ClientChallenge, SrpcReqData}} ->
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
              case srpc_lib:lib_key_create_confirm_response(ExchConnInfo, ClientChallenge,
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
-spec user_exchange({ConnId, Request, SrpcHandler}, Morph) -> Result when
    ConnId   :: conn_id(),
    Request     :: binary(),
    SrpcHandler :: module(),
    Morph       :: boolean(),
    Result      :: ok_response() | error_msg() | invalid_msg().
%%--------------------------------------------------------------------------------------------------
user_exchange({ConnId, ExchangeData, SrpcHandler}, Morph) ->
  case conn_info(ConnId, SrpcHandler) of
    {ok, ConnInfo} ->
      case srpc_lib:user_key_process_exchange_request(ConnInfo, ExchangeData) of
        {ok, ExchangeTerm} ->
          user_key_exchange_request(ConnId, ConnInfo, ExchangeTerm, SrpcHandler, Morph);
        Error ->
          Error
      end;
    Invalid ->
      Invalid
  end.

%%--------------------------------------------------------------------------------------------------
%%   User Key Confirm
%%--------------------------------------------------------------------------------------------------
-spec user_confirm({ConnId, Request, SrpcHandler}) -> Result when
    ConnId   :: conn_id(),
    Request     :: binary(),
    SrpcHandler :: module(),
    Result      :: ok_response() | error_msg() | invalid_msg().
%%--------------------------------------------------------------------------------------------------
user_confirm({ConnId, ConfirmRequest, SrpcHandler}) ->
  case conn_info(ConnId, SrpcHandler) of
    {ok, CryptConnInfo} ->
      case srpc_lib:user_key_process_confirm_request(CryptConnInfo, ConfirmRequest) of
        {ok, {ClientChallenge, SrpcReqConfirmData}} ->
          case SrpcHandler:get_exchange(ConnId) of
            {ok, ExchConnInfo} ->
              SrpcHandler:delete_exchange(ConnId),
              case parse_request_data(SrpcReqConfirmData, SrpcHandler) of
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
                  case srpc_lib:user_key_create_confirm_response(CryptConnInfo, ExchConnInfo,
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
                srpc_lib:user_key_create_confirm_response(CryptConnInfo, invalid,
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
-spec registration({ConnId, Request, SrpcHandler}) -> Result when
    ConnId    :: conn_id(),
    Request     :: binary(),
    SrpcHandler :: module(),
    Result      :: ok_response() | error_msg() | invalid_msg().
%%--------------------------------------------------------------------------------------------------
registration({ConnId, RegistrationRequest, SrpcHandler}) ->
  case conn_info(ConnId, SrpcHandler) of
    {ok, ConnInfo} ->
      case srpc_lib:process_registration_request(ConnInfo, RegistrationRequest) of
        {ok, {RegistrationCode, SrpcRegistrationData, SrpcReqData}} ->
          UserId = maps:get(user_id, SrpcRegistrationData),
          case parse_request_data(SrpcReqData, SrpcHandler) of
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
-spec server_time({ConnId, Request, SrpcHandler}) -> Result when
    ConnId    :: conn_id(),
    Request     :: binary(),
    SrpcHandler :: module(),
    Result      :: ok_response() | error_msg() | invalid_msg().
%%--------------------------------------------------------------------------------------------------
server_time({ConnId, ServerTimeRequest, SrpcHandler}) ->
  case conn_info(ConnId, SrpcHandler) of
    {ok, ConnInfo} ->
      %% To bypass req age check (which needs an estimate of server time), don't use srpc_srv:unwrap
      case srpc_lib:decrypt(origin_client, ConnInfo, ServerTimeRequest) of
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
-spec refresh({ConnId, Request, SrpcHandler}) -> Result when
    ConnId    :: conn_id(),
    Request     :: binary(),
    SrpcHandler :: module(),
    Result      :: ok_response() | error_msg() | invalid_msg().
%%--------------------------------------------------------------------------------------------------
refresh({ConnId, Request, SrpcHandler}) ->
  case conn_info(ConnId, SrpcHandler) of
    {ok, ConnInfo} ->
      case unwrap(ConnInfo, Request, SrpcHandler) of
        {ok, {Nonce, Salt}} ->
          NewConnInfo = srpc_lib:refresh_keys(ConnInfo, Salt),
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
-spec close({ConnId, Request, SrpcHandler}) -> Result when
    ConnId    :: conn_id(),
    Request     :: binary(),
    SrpcHandler :: module(),
    Result      :: ok_response() | error_msg() | invalid_msg().
%%--------------------------------------------------------------------------------------------------
close({ConnId, CloseRequest, SrpcHandler}) ->
  case conn_info(ConnId, SrpcHandler) of
    {ok, ConnInfo} ->
      case unwrap(ConnInfo, CloseRequest, SrpcHandler) of
        {ok, {Nonce, Data}} ->
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
-spec conn_info(ConnId, SrpcHandler) -> Result when
    ConnId    :: conn_id(),
    SrpcHandler :: module(),
    Result      :: {ok, conn_info()} | invalid_msg().
%%--------------------------------------------------------------------------------------------------
conn_info(ConnId, SrpcHandler) ->
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
-spec unwrap(ConnInfo, Data, SrpcHandler) -> Result when
    ConnInfo  :: conn_info(),
    Data        :: binary(),
    SrpcHandler :: module(),
    Result      :: nonced_data() | invalid_msg().
%%--------------------------------------------------------------------------------------------------
unwrap(ConnInfo, Data, SrpcHandler) ->
  case srpc_lib:decrypt(origin_client, ConnInfo, Data) of
    {ok, SrpcData} ->
      parse_request_data(SrpcData, SrpcHandler);
    Invalid ->
      Invalid
  end.

%%--------------------------------------------------------------------------------------------------
%%  Wrap data
%%--------------------------------------------------------------------------------------------------
-spec wrap(ConnInfo, Nonce, Data) -> Result when
    ConnInfo  :: conn_info(),
    Nonce       :: binary(),
    Data        :: binary(),
    Result      :: binary() | error_msg().
%%--------------------------------------------------------------------------------------------------
wrap(ConnInfo, Nonce, Data) ->
  SrpcData = create_srpc_resp_data(Nonce, Data),
  srpc_lib:encrypt(origin_server, ConnInfo, SrpcData).

%%==================================================================================================
%%
%% Private functions
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%%  User key exchange request
%%--------------------------------------------------------------------------------------------------
-spec user_key_exchange_request(ConnId, ConnInfo, {UserId, PublicKey, RequestData}, 
                                SrpcHandler, Morph) -> Result when
    ConnId    :: conn_id(),
    ConnInfo  :: conn_info(),
    UserId      :: user_id(),
    PublicKey   :: exch_key(),
    RequestData :: binary(),
    SrpcHandler :: module(),
    Morph       :: boolean(),
    Result      :: ok_response() | error_msg() | invalid_msg().
%%--------------------------------------------------------------------------------------------------
user_key_exchange_request(ConnId, ConnInfo, {UserId, PublicKey, RequestData}, 
                          SrpcHandler, Morph) ->
  case parse_request_data(RequestData, SrpcHandler) of
    {ok, {Nonce, ReqExchangeData}} ->
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
          user_key_exchange_response(ConnId, ConnInfo, Registration, PublicKey,
                                     RespData, SrpcHandler, Morph);
        undefined ->
          srpc_lib:user_key_create_exchange_response(ConnId, ConnInfo, invalid,
                                                     PublicKey, SrpcRespData)
      end;
    Invalid ->
      Invalid
  end.

%%--------------------------------------------------------------------------------------------------
%%  User key exchange response
%%--------------------------------------------------------------------------------------------------
-spec user_key_exchange_response(ConnId, ConnInfo, Registration, PublicKey, RespData,
                                 SrpcHandler, Morph) -> Result when
    ConnId     :: conn_id(),
    ConnInfo   :: conn_info(),
    Registration :: registration(),
    PublicKey    :: exch_key(),
    RespData     :: binary(),
    SrpcHandler  :: module(),
    Morph        :: boolean(),
    Result       :: ok_response() | error_msg().
%%--------------------------------------------------------------------------------------------------
user_key_exchange_response(ConnId, ConnInfo, Registration, PublicKey, RespData,
                           SrpcHandler, Morph) ->
  UserConnId =
    case Morph of
      true ->
        ConnId;
      _ ->
        SrpcHandler:conn_id()
    end,
  case srpc_lib:user_key_create_exchange_response(UserConnId, ConnInfo, Registration,
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
-spec parse_request_data(Data, SrpcHandler) -> Result when
    Data :: binary(),
    SrpcHandler :: module(),
    Result      :: nonced_data() | invalid_msg().
%%------------------------------------------------------------------------------------------------
parse_request_data(<<?HDR_VSN:?HDR_BITS, ReqTime:?TIME_BITS, 
                   NonceLen:?NONCE_BITS, Nonce:NonceLen/binary,
                   ReqData/binary>>, SrpcHandler) ->
  OKResponse = {ok, {Nonce, ReqData}},
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

parse_request_data(<<_:?HDR_BITS, _Rest/binary>>, _SrpcHandler) ->
  {error, <<"Invalid SRPC header version number">>};

parse_request_data(_ReqData, _SrpcHandler) ->
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
