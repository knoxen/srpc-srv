-module(srpc_handler).

-author("paul@knoxen.com").

-type storage() :: exchange | key | registration.

%%================================================================================================
%% @doc SRPC handler functions
%%
%%================================================================================================
%%------------------------------------------------------------------------------------------------
%% @doc Put <code>Value</code> for <code>Key</code> under storage <code>Type</code>
%%
%% Returns <code>ok</code> or <code>{error, Reason}</code>
%%------------------------------------------------------------------------------------------------
-callback put(Key :: binary(), Value :: term(), Type :: storage()) ->
  ok | {error, Reason :: string()}.

%%------------------------------------------------------------------------------------------------
%% @doc Get value for <code>Key</code> in storage <code>Type</code>
%%
%% Return the <code>value</code> stored or <code>undefined</code>
%%------------------------------------------------------------------------------------------------
-callback get(Key :: binary(), Type :: storage) ->
  {ok, Value :: term()} | undefined.

%%------------------------------------------------------------------------------------------------
%% @doc Delete value for <code>Key</code> in storage <code>Type</code>
%%
%% <code>Type</code> does not include <code>registration</code>, which should be managed
%%  through an existing, valid client and hence should be handled via application API calls.
%%
%% Returns <code>ok</code> or <code>{error, Reason}</code>
%%------------------------------------------------------------------------------------------------
-callback delete(Key :: binary(), Type :: exchange | key) ->
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
