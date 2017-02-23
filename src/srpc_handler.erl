-module(srpc_handler).

-author("paul@knoxen.com").

%%================================================================================================
%%
%% @doc SRPC handler function
%%
%%================================================================================================
%%------------------------------------------------------------------------------------------------
%% @doc Put Value for Key in storage Type
%%
%%------------------------------------------------------------------------------------------------
-callback put(Key :: binary(), Value :: term(), 
              Type :: exchange | agreement | registration) ->
  ok | {error, Reason :: string()}.

%%------------------------------------------------------------------------------------------------
%% @doc Get value for Key in storage Type
%%
%%------------------------------------------------------------------------------------------------
-callback get(Key :: binary(), Type :: exchange | agreement | registration) ->
  {ok, Value :: term()} | undefined.

%%------------------------------------------------------------------------------------------------
%% @doc Delete value for Key in storage Type
%%
%% Note Type does not include registration, which should be managed through an existing,
%% valid client and hence should be handled via application API calls.
%%
%%------------------------------------------------------------------------------------------------
-callback delete(Key :: binary(), Type :: exchange | agreement) ->
  ok | {error, Reason :: string()}.


%% CxTBD Optional functions
