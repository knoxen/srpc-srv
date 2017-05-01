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
-export([lib_exchange/1
        ,lib_confirm/2
        ,registration/2
        ,user_exchange/2
        ,user_confirm/2
        ,encrypt_data/3
        ,decrypt_data/3
        ,client_map_for_id/1
        ,server_epoch/2
        ,refresh/2
        ,close/2
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
lib_exchange(ExchangeRequest) ->
  case srpc_lib:lib_key_process_exchange_request(ExchangeRequest) of
    {ok, {ClientPublicKey, ReqExchangeData}} ->
      RespExchangeData = 
        case erlang:function_exported(app_srpc_handler, lib_exchange_data, 1) of
          true ->
            app_srpc_handler:lib_exchange_data(ReqExchangeData);
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
%%   Lib Key Confirm
%%
%%------------------------------------------------------------------------------------------------
lib_confirm(ClientId, ConfirmRequest) ->
  case app_srpc_handler:get(ClientId, exchange) of
    {ok, ExchangeMap} ->
      app_srpc_handler:delete(ClientId, exchange),
      case srpc_lib:lib_key_process_confirm_request(ExchangeMap, ConfirmRequest) of
        {ok, {_ReqClientId, ClientChallenge, SrpcReqData}} ->
          {Nonce, ConfirmReqData} = extract_nonce_req_data(SrpcReqData),
          case Nonce of
            error ->
              {Nonce, ConfirmReqData};
            _ ->
              ConfirmRespData = 
                case erlang:function_exported(app_srpc_handler, lib_confirm_data, 1) of
                  true ->
                    app_srpc_handler:lib_confirm_data(ConfirmReqData);
                  false ->
                    <<>>
                end,
              SrpcRespData = create_srpc_resp_data(ConfirmRespData),
              case srpc_lib:lib_key_create_confirm_response(ExchangeMap, ClientChallenge,
                                                               SrpcRespData) of
                {ok, ClientMap, ConfirmResponse} ->
                  case app_srpc_handler:put(ClientId, ClientMap, key) of
                    ok ->
                      {ok, ConfirmResponse};
                    Error ->
                      Error
                  end;
                {invalid, _ClientMap, ConfirmResponse} ->
                  {ok, ConfirmResponse};
                Error ->
                  Error
              end
          end;
        Error ->
          Error
      end;
    undefined ->
      {invalid, <<"No exchange info for Client Id: ", ClientId/binary>>}
  end.

%%================================================================================================
%%
%% Registration
%%
%%================================================================================================
registration(ClientId, RegistrationRequest) ->
  case client_map_for_id(ClientId) of
    {ok, ClientMap} ->
      case srpc_lib:process_registration_request(ClientMap, RegistrationRequest) of
        {ok, {RegistrationCode, SrpcRegistrationData, SrpcReqData}} ->
          UserId = maps:get(user_id, SrpcRegistrationData),
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
                      case app_srpc_handler:put(UserId, SrpcRegistrationData, registration) of
                        ok ->
                          srpc_lib:create_registration_response(ClientMap,
                                                                ?SRPC_REGISTRATION_OK,
                                                                SrpcRespData);
                        _Error ->
                          srpc_lib:create_registration_response(ClientMap,
                                                                ?SRPC_REGISTRATION_ERROR,
                                                                SrpcRespData)
                      end;
                    {ok, _SrpcRegistrationData} ->
                      srpc_lib:create_registration_response(ClientMap,
                                                            ?SRPC_REGISTRATION_DUP,
                                                            SrpcRespData)
                  end;
                ?SRPC_REGISTRATION_UPDATE ->
                  case app_srpc_handler:get(UserId, registration) of
                    {ok, _PrevSrpcRegistrationData} ->
                      case app_srpc_handler:put(UserId, SrpcRegistrationData, registration) of
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
user_exchange(ClientId, ExchangeRequest) ->
  case client_map_for_id(ClientId) of
    {ok, ClientMap} ->
      case srpc_lib:user_key_process_exchange_request(ClientMap, ExchangeRequest) of
        {ok, {UserId, ClientPublicKey, SrpcReqData}} ->
          case extract_req_data(SrpcReqData) of
            {ok, ReqExchangeData} ->
              RespExchangeData = 
                case erlang:function_exported(app_srpc_handler, user_exchange_data, 2) of
                  true ->
                    app_srpc_handler:user_exchange_data(UserId, ReqExchangeData);
                  false ->
                    <<>>
                end,
              SrpcRespData = create_srpc_resp_data(RespExchangeData),
              case app_srpc_handler:get(UserId, registration) of
                {ok, SrpcRegistrationData} ->
                  case srpc_lib:user_key_create_exchange_response(ClientMap,
                                                                  SrpcRegistrationData,
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
                  srpc_lib:user_key_create_exchange_response(ClientMap, invalid, 
                                                             ClientPublicKey, SrpcRespData)
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
%%   User Key Confirm
%%
%%------------------------------------------------------------------------------------------------
user_confirm(ClientId, ConfirmRequest) ->
  case client_map_for_id(ClientId) of
    {ok, CryptClientMap} ->
      case srpc_lib:user_key_process_confirm_request(CryptClientMap, ConfirmRequest) of
        {ok, {UserClientId, ClientChallenge, SrpcReqConfirmData}} ->
          case app_srpc_handler:get(UserClientId, exchange) of
            {ok, ExchangeMap} ->
              app_srpc_handler:delete(UserClientId, exchange),
              case extract_req_data(SrpcReqConfirmData) of
                {ok, ReqConfirmData} ->
                  UserId = maps:get(entity_id, ExchangeMap),
                  RespConfirmData = 
                    case erlang:function_exported(app_srpc_handler, user_confirm_data, 2) of
                      true ->
                        app_srpc_handler:user_confirm_data(UserId, ReqConfirmData);
                      false ->
                        <<>>
                    end,
                  SrpcRespData = create_srpc_resp_data(RespConfirmData),
                  case srpc_lib:user_key_create_confirm_response(CryptClientMap, ExchangeMap,
                                                                    ClientChallenge,
                                                                    SrpcRespData) of
                    {ok, ClientMap, ConfirmResponse} ->
                      ClientMap2 = maps:put(client_id, UserClientId, ClientMap),
                      case app_srpc_handler:put(UserClientId, ClientMap2, key) of
                        ok ->
                          {ok, ConfirmResponse};
                        Error ->
                          Error
                      end;
                    {invalid, _ClientMap, ConfirmResponse} ->
                      %% CxTBD Report invalid
                      {ok, ConfirmResponse}
                  end;
                InvalidError ->
                  InvalidError
              end;
            undefined ->
              SrpcRespData = create_srpc_resp_data(<<>>),
              {_, _ClientMap, ConfirmResponse} =
                srpc_lib:user_key_create_confirm_response(CryptClientMap, invalid,
                                                             ClientChallenge, SrpcRespData),
              {ok, ConfirmResponse}
          end
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
      %% To bypass req age check (which needs an accurate server epoch), don't use decrypt_data 
      case srpc_lib:decrypt(origin_client, ClientMap, ServerEpochRequest) of
        {ok, Nonce} ->
          DataEpoch = epoch_seconds(),
          RespData = <<DataEpoch:?EPOCH_BITS, Nonce/binary>>,
          %% Don't use encrypt_data since we're passing back the epoch directly (as resp data)
          srpc_lib:encrypt(origin_server, ClientMap, RespData);
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
refresh(ClientId, RefreshRequest) ->
  case client_map_for_id(ClientId) of
    {ok, ClientMap} ->
      case decrypt_data(origin_client, ClientMap, RefreshRequest) of
        {ok, Data} ->
          NewClientMap = srpc_lib:refresh_keys(ClientMap, Data),
          case app_srpc_handler:put(ClientId, NewClientMap, key) of
            ok ->
              encrypt_data(origin_server, NewClientMap, Data);
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
close(ClientId, CloseRequest) ->
  case client_map_for_id(ClientId) of
    {ok, ClientMap} ->
      case decrypt_data(origin_client, ClientMap, CloseRequest) of
        {ok, ClientId} ->
          app_srpc_handler:delete(ClientId, key),
          encrypt_data(origin_server, ClientMap, ClientId);
        {ok, _ClientId} ->
          {error, <<"Attempt to close another ClientId">>};
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
client_map_for_id(ClientId) when is_binary(ClientId) ->
  case app_srpc_handler:get(ClientId, exchange) of
    undefined ->
      case app_srpc_handler:get(ClientId, key) of
        undefined ->
          {invalid, <<"Invalid ClientId: ", ClientId/binary>>};
        Result ->
          Result
      end;
    Result ->
      Result
  end;
client_map_for_id(_) ->
  {invalid, <<"Invalid ClientId: Missing">>}.

%%================================================================================================
%%
%% Encrypt / Decrypt
%%
%%================================================================================================
encrypt_data(Origin, ClientMap, Data) ->
  SrpcData = create_srpc_resp_data(Data),
  srpc_lib:encrypt(Origin, ClientMap, SrpcData).

decrypt_data(Origin, ClientMap, Data) ->
  case srpc_lib:decrypt(Origin, ClientMap, Data) of
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
extract_nonce_req_data(<<NonceLen:?NONCE_BITS, MoreData/binary>>) ->
  case NonceLen of
    0 ->
      {error, <<"Invalid lib key req nonce len of 0">>};
    _ ->
      case MoreData of
        <<NonceData:NonceLen/binary, Data/binary>> ->
          erlang:put(nonce, NonceData),
          {NonceData, Data};
        _ ->
          {error, <<"Invalid nonce len longer than available data">>}
      end
  end.        

extract_req_data(<<?HDR_VSN:?HDR_BITS, ReqEpoch:?EPOCH_BITS, MoreData/binary>>) ->
  {Nonce, ReqData} = extract_nonce_req_data(MoreData),
  case Nonce of
    error ->
      {Nonce, ReqData};
    _ ->
      case erlang:function_exported(app_srpc_handler, req_age_tolerance, 0) of
        false ->
          {ok, ReqData};
        true ->
          case app_srpc_handler:req_age_tolerance() of
            Tolerance when 0 < Tolerance ->
              SysEpoch = epoch_seconds(),
              ReqAge = abs(SysEpoch - ReqEpoch),
              case ReqAge =< Tolerance of
                true ->
                  case erlang:byte_size(Nonce) of
                    0 ->
                      {ok, ReqData};
                    _ ->
                      case erlang:function_exported(app_srpc_handler, nonce, 1) of
                        true ->
                          case app_srpc_handler:nonce(Nonce) of
                            true ->
                              {ok, ReqData};
                            false ->
                              {invalid, <<"Repeated nonce: ", Nonce/binary>>}
                          end;
                        false ->
                          {ok, ReqData}
                      end
                  end;
                false ->
                  Age = erlang:list_to_binary(io_lib:format("~B", [ReqAge])),
                  {invalid, <<"Request age: ", Age/binary>>}
              end;
            _ ->
              {ok, ReqData}
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
