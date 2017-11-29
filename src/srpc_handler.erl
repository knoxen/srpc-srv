-module(srpc_handler).

-author("paul@knoxen.com").

-include ("srpc_srv.hrl").

%%================================================================================================
%% @doc SRPC handler functions
%%
%%================================================================================================
%%------------------------------------------------------------------------------------------------
%% @doc Generate Client ID
%%
%% Generate a probabilistically uniquie Client ID. For explicit control over the characteristics
%% of the generated Client ID consider using either the
%% <a href=https://github.com/EntropyString/Erlang>Erlang</a> or
%% <a href=https://github.com/EntropyString/Elixir>Elixir</a> version of EntropyString.
%%
%% Returns binary <code>ClientId</code>
%%------------------------------------------------------------------------------------------------
-callback client_id() -> 
  ClientID :: binary().

%%------------------------------------------------------------------------------------------------
%% @doc Put <code>ClientInfo</code> for <code>ClientId</code> in exchange store.
%%
%% Returns <code>ok</code> or <code>{error, Reason}</code>
%%------------------------------------------------------------------------------------------------
-callback put_exchange(ClientId :: client_id(), ClientInfo :: client_info()) ->
  ok | error_msg().

%%------------------------------------------------------------------------------------------------
%% @doc Put <code>ClientInfo</code> for <code>ClientId</code> in client store.
%%
%% Returns <code>ok</code> or <code>{error, Reason}</code>
%%------------------------------------------------------------------------------------------------
-callback put_client(ClientId :: client_id(), ClientInfo :: client_info()) ->
  ok | error_msg().

%%------------------------------------------------------------------------------------------------
%% @doc Put <code>Registration</code> for <code>UserId</code> in registration store.
%%
%% Returns <code>ok</code> or <code>{error, Reason}</code>
%%------------------------------------------------------------------------------------------------
-callback put_registration(UserId :: user_id(), Registration :: registration()) ->
  ok | error_msg().

%%------------------------------------------------------------------------------------------------
%% @doc Get <code>ClientInfo</code> for <code>ClientId</code> from the exchange store.
%%
%% Return the stored <code>ClientInfo</code> or <code>undefined</code>.
%%------------------------------------------------------------------------------------------------
%% -spec get_exchange(ClientId) -> Result when
%%     ClientId :: client_id(),
%%     Result   :: {ok, client_info()} | undefined.
%%------------------------------------------------------------------------------------------------
-callback get_exchange(ClientId :: client_id()) ->
  {ok, ClientInfo :: client_info()} | undefined.

%%------------------------------------------------------------------------------------------------
%% @doc Get <code>ClientInfo</code> for <code>ClientId</code> from the client store.
%%
%% Return the stored <code>ClientInfo</code> or <code>undefined</code>.
%%------------------------------------------------------------------------------------------------
-callback get_client(ClientId :: client_id()) ->
  {ok, ClientInfo :: client_info()} | undefined.

%%------------------------------------------------------------------------------------------------
%% @doc Get <code>Registration</code> for <code>UserId</code> from the registration store.
%%
%% Return the stored <code>Registration</code> or <code>undefined</code>.
%%------------------------------------------------------------------------------------------------
-callback get_registration(UserId :: user_id()) ->
  {ok, Registration :: registration()} | undefined.

%%------------------------------------------------------------------------------------------------
%% @doc Delete <code>ClientId</code> in the exchange store.
%%
%% Returns <code>ok</code> or <code>{error, Reason}</code>
%%------------------------------------------------------------------------------------------------
-callback delete_exchange(ClientId :: client_id()) ->
  ok | {error, Reason :: string()}.

%%------------------------------------------------------------------------------------------------
%% @doc Delete <code>ClientId</code> in the client store.
%%
%% Returns <code>ok</code> or <code>{error, Reason}</code>
%%------------------------------------------------------------------------------------------------
-callback delete_client(ClientId :: binary()) ->
  ok | {error, Reason :: string()}.

%% CxTBD Optional functions
%%
%% req_age_tolerance/0
%%   - Max time in seconds to consider a request as valid
%%
%% nonce/1
%%   - Handle request nonce
%%
%% lib_exchange_data/1
%%   - Handle application specific client data included in lib key exchange message
%%
%% lib_confirm_data/1
%%   - Handle application specific client data included in lib key confirm message
%%
%% registration_data/1
%%   - Handle application specific client data included in registration message
%% 
%% user_exchange_data/1
%%   - Handle application specific client data included in user key exchange message
%%
%% user_confirm_data/1
%%   - Handle application specific client data included in user key confirm message
%%
