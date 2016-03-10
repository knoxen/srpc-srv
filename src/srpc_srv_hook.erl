-module(srpc_srv_hook).

-author("paul@knoxen.com").

-callback exchange_put(Id :: binary(), Value :: term()) ->
  ok | {error, Reason :: string()}.

-callback exchange_get(Id :: binary()) ->
  {ok, Value :: term()} | undefined.

-callback exchange_delete(Id :: binary()) ->
  ok | {error, Reason :: string()}.

-callback channel_put(Type :: atom, Id :: binary(), Value :: term()) ->
  ok | {error, Reason :: string()}.

-callback channel_get(Type :: atom, Id :: binary()) ->
  {ok, Value :: term()} | undefined.

-callback channel_delete(Type :: atom, Id :: binary()) ->
  ok | {error, Reason :: string()}.

-callback user_put(Id :: binary(), Value :: term()) ->
  ok | {error, Reason :: string()}.

-callback user_get(Id :: binary()) ->
  {ok, Value :: term()} | undefined.
