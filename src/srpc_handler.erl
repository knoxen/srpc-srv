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
              Type :: exchange | lib | user | registration) ->
  ok | {error, Reason :: string()}.

%%------------------------------------------------------------------------------------------------
%% @doc Get value for Key in storage Type
%%
%%------------------------------------------------------------------------------------------------
-callback get(Key :: binary(), Type :: exchange | lib | user | registration) ->
  {ok, Value :: term()} | undefined.

%%------------------------------------------------------------------------------------------------
%% @doc Delete value for Key in storage Type
%%
%% Note Type does not include registration, which should be managed through an existing,
%% valid lib or user client and hence should be handled via application API calls.
%%
%%------------------------------------------------------------------------------------------------
-callback delete(Key :: binary(), Type :: exchange | lib | user) ->
  ok | {error, Reason :: string()}.


%% CxTBD Optional functions
