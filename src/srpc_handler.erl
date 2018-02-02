-module(srpc_handler).

-author("paul@knoxen.com").

-include ("srpc_srv.hrl").

%%================================================================================================
%% @doc SRPC handler functions
%%
%%================================================================================================
%%------------------------------------------------------------------------------------------------
%% @doc Generate Connection ID
%%
%% Generate a probabilistically uniquie Connection ID. For explicit control over the characteristics
%% of the generated Connection ID consider using either the
%% <a href=https://github.com/EntropyString/Erlang>Erlang</a> or
%% <a href=https://github.com/EntropyString/Elixir>Elixir</a> version of EntropyString.
%%
%% Returns binary <code>ConnId</code>
%%------------------------------------------------------------------------------------------------
-callback conn_id() -> 
  ConnID :: binary().

%%------------------------------------------------------------------------------------------------
%% @doc Put <code>Conn</code> for <code>ConnId</code> in exchange store.
%%
%% Returns <code>ok</code> or <code>{error, Reason}</code>
%%------------------------------------------------------------------------------------------------
-callback put_exchange(ConnId :: conn_id(), Conn :: conn()) ->
  ok | error_msg().

%%------------------------------------------------------------------------------------------------
%% @doc Put <code>Conn</code> for <code>ConnId</code> in conn store.
%%
%% Returns <code>ok</code> or <code>{error, Reason}</code>
%%------------------------------------------------------------------------------------------------
-callback put_conn(ConnId :: conn_id(), Conn :: conn()) ->
  ok | error_msg().

%%------------------------------------------------------------------------------------------------
%% @doc Put <code>Registration</code> for <code>UserId</code> in registration store.
%%
%% Returns <code>ok</code> or <code>{error, Reason}</code>
%%------------------------------------------------------------------------------------------------
-callback put_registration(UserId :: user_id(), Registration :: registration()) ->
  ok | error_msg().

%%------------------------------------------------------------------------------------------------
%% @doc Get <code>Conn</code> for <code>ConnId</code> from the exchange store.
%%
%% Return the stored <code>Conn</code> or <code>undefined</code>.
%%------------------------------------------------------------------------------------------------
%% -spec get_exchange(ConnId) -> Result when
%%     ConnId :: conn_id(),
%%     Result   :: {ok, conn()} | undefined.
%%------------------------------------------------------------------------------------------------
-callback get_exchange(ConnId :: conn_id()) ->
  {ok, Conn :: conn()} | undefined.

%%------------------------------------------------------------------------------------------------
%% @doc Get <code>Conn</code> for <code>ConnId</code> from the conn store.
%%
%% Return the stored <code>Conn</code> or <code>undefined</code>.
%%------------------------------------------------------------------------------------------------
-callback get_conn(ConnId :: conn_id()) ->
  {ok, Conn :: conn()} | undefined.

%%------------------------------------------------------------------------------------------------
%% @doc Get <code>Registration</code> for <code>UserId</code> from the registration store.
%%
%% Return the stored <code>Registration</code> or <code>undefined</code>.
%%------------------------------------------------------------------------------------------------
-callback get_registration(UserId :: user_id()) ->
  {ok, Registration :: registration()} | undefined.

%%------------------------------------------------------------------------------------------------
%% @doc Delete <code>ConnId</code> in the exchange store.
%%
%% Returns <code>ok</code> or <code>{error, Reason}</code>
%%------------------------------------------------------------------------------------------------
-callback delete_exchange(ConnId :: conn_id()) ->
  ok | {error, Reason :: string()}.

%%------------------------------------------------------------------------------------------------
%% @doc Delete <code>ConnId</code> in the conn store.
%%
%% Returns <code>ok</code> or <code>{error, Reason}</code>
%%------------------------------------------------------------------------------------------------
-callback delete_conn(ConnId :: binary()) ->
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
%%   - Handle application specific conn data included in lib key exchange message
%%
%% lib_confirm_data/1
%%   - Handle application specific conn data included in lib key confirm message
%%
%% registration_data/1
%%   - Handle application specific conn data included in registration message
%% 
%% user_exchange_data/1
%%   - Handle application specific conn data included in user key exchange message
%%
%% user_confirm_data/1
%%   - Handle application specific conn data included in user key confirm message
%%
