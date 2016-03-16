-module(srpc_hook).

-author("paul@knoxen.com").

%% CxInc doc
-callback put(Type :: atom, Id :: binary(), Value :: term()) ->
  ok | {error, Reason :: string()}.

-callback get(Type :: atom, Id :: binary()) ->
  {ok, Value :: term()} | undefined.

-callback delete(Type :: atom, Id :: binary()) ->
  ok | {error, Reason :: string()}.
