-module(srpc_srv).

-author("paul@knoxen.com").

%%================================================================================================
%%
%% API exports
%%
%%================================================================================================
-export([parse_packet/2
        ,lib_exchange/2
        ,srpc_action/2
        ,decrypt/4
        ,encrypt/4
        ]).

%%================================================================================================
%%
%% Registration Codes
%%
%%================================================================================================
-define(HDR_VSN,     1).
-define(HDR_BITS,    8).
-define(TIME_BITS,  32).
-define(NONCE_BITS,  8).

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
%% SRPC Message Handling
%%
%%================================================================================================
%%------------------------------------------------------------------------------------------------
%%
%%   Parse Packet
%%
%%------------------------------------------------------------------------------------------------
parse_packet(<<16#00, Data/binary>>, _SrpcHandler) ->
  {lib_exchange, Data};
parse_packet(<<16#10, IdLen:8, Id:IdLen/binary, Data/binary>>, SrpcHandler) ->
  packet_client({srpc_action, Id, Data}, SrpcHandler);
parse_packet(<<16#ff, IdLen:8, Id:IdLen/binary, Data/binary>>, SrpcHandler) ->
  packet_client({app_request, Id, Data}, SrpcHandler);
parse_packet(_, _SrpcHandler) ->
  {error, <<"Invalid SRPC packet">>}.

packet_client({Type, Id, Data}, SrpcHandler) ->
  case client_info(Id, SrpcHandler) of
    {ok, ClientInfo} ->
      {Type, ClientInfo, Data};
    Invalid ->
      Invalid
  end.

%%------------------------------------------------------------------------------------------------
%%
%%   Route SRPC Actions
%%
%%------------------------------------------------------------------------------------------------
srpc_action(<<16#10, L:8, ClientId:L/binary, SrpcCode:8, ActionData/binary>>, SrpcHandler) ->
  srpc_route(SrpcCode, {ClientId, ActionData, SrpcHandler});

srpc_action(_, _) -> {undefined, {error, <<"Invalid srpc action packet">>}}.

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
lib_exchange(<<16#00, ExchangeRequest/binary>>, SrpcHandler) ->
  case srpc_lib:lib_key_process_exchange_request(ExchangeRequest) of
    {ok, {ClientPublicKey, ReqExchangeData}} ->
      RespExchangeData =
        case erlang:function_exported(SrpcHandler, lib_exchange_data, 1) of
          true ->
            app_srpc_handler:lib_exchange_data(ReqExchangeData);
          false ->
            <<>>
        end,
      ClientId = SrpcHandler:client_id(),
      case srpc_lib:lib_key_create_exchange_response(ClientId, ClientPublicKey, RespExchangeData) of
        {ok, {ExchangeMap, ExchangeResponse}} ->
          ClientId = maps:get(client_id, ExchangeMap),
          case SrpcHandler:put(ClientId, ExchangeMap, exchange) of
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
%%   Lib Key Agreement Confirm
%%
%%------------------------------------------------------------------------------------------------
lib_confirm({ClientId, ConfirmRequest, SrpcHandler}) ->
  case SrpcHandler:get(ClientId, exchange) of
    {ok, ExchangeMap} ->
      SrpcHandler:delete(ClientId, exchange),
      case srpc_lib:lib_key_process_confirm_request(ExchangeMap, ConfirmRequest) of
        {ok, {ClientChallenge, SrpcReqData}} ->
          case extract_time_data(SrpcReqData) of
            {ok, {_ClientTime, Nonce, ConfirmReqData}} ->
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
              case srpc_lib:lib_key_create_confirm_response(ExchangeMap, ClientChallenge,
                                                            SrpcRespData) of
                {ok, ClientInfo, ConfirmResponse} ->

                  srpc_util:debug_info(?MODULE, lib_confirm, ClientInfo),


                  case SrpcHandler:put(ClientId, ClientInfo, key) of
                    ok ->
                      {ok, ConfirmResponse};
                    Error ->
                      Error
                  end;
                {invalid, _ClientInfo, ConfirmResponse} ->
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
      {invalid, <<"No exchange info for Client Id: ", ClientId/binary>>}
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
user_exchange({ClientId, ExchangeRequest, SrpcHandler}, Morph) ->
  case client_info(ClientId, SrpcHandler) of
    {ok, ClientInfo} ->
 srpc_util:debug_info(?MODULE, user_exchange, ClientInfo),
      case srpc_lib:user_key_process_exchange_request(ClientInfo, ExchangeRequest) of
        {ok, ExchangeTerm} ->
          user_key_exchange_request(ClientId, ClientInfo, ExchangeTerm, SrpcHandler, Morph);
        Error ->
          Error
      end;
    Invalid ->
      Invalid
  end.

%%------------------------------------------------------------------------------------------------
%%
%%   User Key Confirm
%%
%%------------------------------------------------------------------------------------------------
user_confirm({ClientId, ConfirmRequest, SrpcHandler}) ->
  case client_info(ClientId, SrpcHandler) of
    {ok, CryptClientInfo} ->
      case srpc_lib:user_key_process_confirm_request(CryptClientInfo, ConfirmRequest) of
        {ok, {ClientChallenge, SrpcReqConfirmData}} ->
          case SrpcHandler:get(ClientId, exchange) of
            {ok, ExchangeMap} ->
              SrpcHandler:delete(ClientId, exchange),
              case extract_req_data(SrpcReqConfirmData, SrpcHandler) of
                {ok, {Nonce, ReqConfirmData}} ->
                  UserId = maps:get(entity_id, ExchangeMap),
                  RespConfirmData =
                    case erlang:function_exported(SrpcHandler, user_confirm_data, 2) of
                      true ->
                        SrpcHandler:user_confirm_data(UserId, ReqConfirmData);
                      false ->
                        <<>>
                    end,
                  SrpcRespData = create_srpc_resp_data(Nonce, RespConfirmData),
                  case srpc_lib:user_key_create_confirm_response(CryptClientInfo, ExchangeMap,
                                                                 ClientChallenge,
                                                                 SrpcRespData) of
                    {ok, ClientInfo, ConfirmResponse} ->
                      ClientInfo2 = maps:put(client_id, ClientId, ClientInfo),
                      case SrpcHandler:put(ClientId, ClientInfo2, key) of
                        ok ->
                          {ok, ConfirmResponse};
                        Error ->
                          Error
                      end;
                    {invalid, _ClientInfo, ConfirmResponse} ->
                      %% CxTBD Report invalid
                      {ok, ConfirmResponse}
                  end;
                InvalidError ->
                  InvalidError
              end;
            undefined ->
              Nonce = crypto:strong_rand_bytes(erlang:trunc(?NONCE_BITS/8)),
              SrpcRespData = create_srpc_resp_data(Nonce, <<>>),
              {_, _ClientInfo, ConfirmResponse} =
                srpc_lib:user_key_create_confirm_response(CryptClientInfo, invalid,
                                                          ClientChallenge, SrpcRespData),
              {ok, ConfirmResponse}
          end;
        Error ->
          Error
      end;
    Invalid ->
      Invalid
  end.

%%================================================================================================
%%
%% Registration
%%
%%================================================================================================
registration({ClientId, RegistrationRequest, SrpcHandler}) ->
  case client_info(ClientId, SrpcHandler) of
    {ok, ClientInfo} ->
      case srpc_lib:process_registration_request(ClientInfo, RegistrationRequest) of
        {ok, {RegistrationCode, SrpcRegistrationData, SrpcReqData}} ->
          UserId = maps:get(user_id, SrpcRegistrationData),
          case extract_req_data(SrpcReqData, SrpcHandler) of
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
                  case SrpcHandler:get(UserId, registration) of
                    undefined ->
                      case SrpcHandler:put(UserId, SrpcRegistrationData, registration) of
                        ok ->
                          srpc_lib:create_registration_response(ClientInfo,
                                                                ?SRPC_REGISTRATION_OK,
                                                                SrpcRespData);
                        _Error ->
                          srpc_lib:create_registration_response(ClientInfo,
                                                                ?SRPC_REGISTRATION_ERROR,
                                                                SrpcRespData)
                      end;
                    {ok, _SrpcRegistrationData} ->
                      srpc_lib:create_registration_response(ClientInfo,
                                                            ?SRPC_REGISTRATION_DUP,
                                                            SrpcRespData)
                  end;
                ?SRPC_REGISTRATION_UPDATE ->
                  case SrpcHandler:get(UserId, registration) of
                    {ok, _PrevSrpcRegistrationData} ->
                      case SrpcHandler:put(UserId, SrpcRegistrationData, registration) of
                        ok ->
                          srpc_lib:create_registration_response(ClientInfo,
                                                                ?SRPC_REGISTRATION_OK,
                                                                SrpcRespData);
                        _Error ->
                          srpc_lib:create_registration_response(ClientInfo,
                                                                ?SRPC_REGISTRATION_ERROR,
                                                                SrpcRespData)
                      end;
                    undefined ->
                      srpc_lib:create_registration_response(ClientInfo,
                                                            ?SRPC_REGISTRATION_NOT_FOUND,
                                                            SrpcRespData)
                  end;
                _ ->
                  srpc_lib:create_registration_response(ClientInfo,
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
%% Server Time
%%
%%================================================================================================
server_time({ClientId, ServerTimeRequest, SrpcHandler}) ->
  case client_info(ClientId, SrpcHandler) of
    {ok, ClientInfo} ->
      %% To bypass req age check (which needs an accurate server time), don't use srpc_srv:decrypt
      case srpc_lib:decrypt(origin_client, ClientInfo, ServerTimeRequest) of
        {ok, ReqData} ->
          case extract_time_data(ReqData) of
            {ok, {_ClientTime, Nonce, Data}} ->
              Time = system_time(),
              TimeRespData = <<Time:?TIME_BITS, Data/binary>>,
              encrypt(origin_server, ClientInfo, Nonce, TimeRespData);
            Error ->
              Error
          end;
        Error ->
          Error
      end;
    Invalid ->
      Invalid
  end.

%%================================================================================================
%%
%% Refresh Srpc Keys
%%
%%================================================================================================
refresh({ClientId, RefreshRequest, SrpcHandler}) ->
  case client_info(ClientId, SrpcHandler) of
    {ok, ClientInfo} ->
      case decrypt(origin_client, ClientInfo, RefreshRequest, SrpcHandler) of
        {ok, {Nonce, Data}} ->
          NewClientInfo = srpc_lib:refresh_keys(ClientInfo, Data),
          case SrpcHandler:put(ClientId, NewClientInfo, key) of
            ok ->
              encrypt(origin_server, NewClientInfo, Nonce, Data);
            Error ->
              Error
          end;
        Error ->
          Error
      end;
    Invalid ->
      Invalid
  end.

%%================================================================================================
%%
%% Client Close
%%
%%================================================================================================
close({ClientId, CloseRequest, SrpcHandler}) ->
  case client_info(ClientId, SrpcHandler) of
    {ok, ClientInfo} ->
      case decrypt(origin_client, ClientInfo, CloseRequest, SrpcHandler) of
        {ok, {Nonce, Data}} ->
          SrpcHandler:delete(ClientId, key),
          encrypt(origin_server, ClientInfo, Nonce, Data);
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
client_info(ClientId, SrpcHandler) when is_binary(ClientId) ->
  case SrpcHandler:get(ClientId, exchange) of
    undefined ->
      case SrpcHandler:get(ClientId, key) of
        undefined ->
          {invalid, <<"Invalid ClientId: ", ClientId/binary>>};
        Result ->
          Result
      end;
    Result ->
      Result
  end;
client_info(_, _SrpcHandler) ->
  {invalid, <<"Invalid ClientId: Missing">>}.

%%================================================================================================
%%
%% Decrypt / Encrypt
%%
%%================================================================================================
decrypt(Origin, ClientInfo, Data, SrpcHandler) ->
  case srpc_lib:decrypt(Origin, ClientInfo, Data) of
    {ok, SrpcData} ->
      extract_req_data(SrpcData, SrpcHandler);
    InvalidError ->
      InvalidError
  end.

encrypt(Origin, ClientInfo, Nonce, Data) ->
  SrpcData = create_srpc_resp_data(Nonce, Data),
  srpc_lib:encrypt(Origin, ClientInfo, SrpcData).

%%================================================================================================
%%
%% Private functions
%%
%%================================================================================================
%%------------------------------------------------------------------------------------------------
%%
%%------------------------------------------------------------------------------------------------
user_key_exchange_request(ClientId, ClientInfo, {UserId, PublicKey, RequestData}, 
                          SrpcHandler, Morph) ->
  case extract_req_data(RequestData, SrpcHandler) of
    {ok, {Nonce, ReqExchangeData}} ->
      RespExchangeData =
        case erlang:function_exported(SrpcHandler, user_exchange_data, 2) of
          true ->
            SrpcHandler:user_exchange_data(UserId, ReqExchangeData);
          false ->
            <<>>
        end,
      SrpcRespData = create_srpc_resp_data(Nonce, RespExchangeData),
      case SrpcHandler:get(UserId, registration) of
        {ok, SrpcRegistrationData} ->
          case Morph of
            true ->
              user_key_exchange_response(ClientId, ClientInfo, SrpcRegistrationData,
                                         PublicKey, RespExchangeData, SrpcHandler);
            _ ->
              UserClientId = SrpcHandler:client_id(),
              UserClientInfo = maps:put(client_id, UserClientId, ClientInfo),
              user_key_exchange_response(UserClientId, UserClientInfo, SrpcRegistrationData,
                                         PublicKey, RespExchangeData, SrpcHandler)
          end;
        undefined ->
          srpc_lib:user_key_create_exchange_response(ClientId, ClientInfo, invalid,
                                                     PublicKey, SrpcRespData)
      end;
    InvalidError ->
      InvalidError
  end.

%%------------------------------------------------------------------------------------------------
%%
%%------------------------------------------------------------------------------------------------
user_key_exchange_response(ClientId, ClientInfo, RegData, PublicKey, RespData, SrpcHandler) ->
  case srpc_lib:user_key_create_exchange_response(ClientId, ClientInfo, RegData, 
                                                  PublicKey, RespData) of
    {ok, {ExchangeMap, ExchangeResponse}} ->
  srpc_util:debug_info(?MODULE, user_exchange, ExchangeMap),
      ExchangeClientId = maps:get(client_id, ExchangeMap),
      case SrpcHandler:put(ExchangeClientId, ExchangeMap, exchange) of
        ok ->
          {ok, ExchangeResponse};
        Error ->
          Error
      end;
    Error ->
      Error
  end.

%%------------------------------------------------------------------------------------------------
%%
%%------------------------------------------------------------------------------------------------
extract_time_data(<<?HDR_VSN:?HDR_BITS, ClientTime:?TIME_BITS,
                    NonceLen:?NONCE_BITS, Nonce:NonceLen/binary,
                    Data/binary>>) ->
  {ok, {ClientTime, Nonce, Data}};
extract_time_data(_) ->
  {error, <<"Invalid lib confirm packet">>}.


%%------------------------------------------------------------------------------------------------
%%
%%------------------------------------------------------------------------------------------------
extract_req_data(<<?HDR_VSN:?HDR_BITS, ReqTime:?TIME_BITS, 
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
                          {invalid, <<"Repeated nonce: ", Nonce/binary>>}
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
extract_req_data(<<_:?HDR_BITS, _Rest/binary>>, _SrpcHandler) ->
  {error, <<"Invalid SRPC header version number">>};
extract_req_data(_ReqData, _SrpcHandler) ->
  {error, <<"Invalid SRPC request data">>}.

%%------------------------------------------------------------------------------------------------
%%
%%------------------------------------------------------------------------------------------------
create_srpc_resp_data(Nonce, RespData) ->
  NonceLen = erlang:byte_size(Nonce),
  Time = system_time(),
  <<?HDR_VSN:?HDR_BITS, Time:?TIME_BITS, NonceLen:?NONCE_BITS, Nonce/binary, RespData/binary>>.

%%------------------------------------------------------------------------------------------------
%%  
%%------------------------------------------------------------------------------------------------
system_time() ->
  erlang:system_time(second).
