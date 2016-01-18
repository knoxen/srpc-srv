-module(srpc_handler).

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

-callback lib_key_exchange_data(ReqData :: binary()) ->
  RespData :: binary().

-callback lib_key_validation_data(ReqData :: binary()) ->
  RespData :: binary().

-callback registration_data(UserId :: binary(), ReqData :: binary()) ->
  RespData :: binary().

-callback user_key_exchange_data(UserId :: binary(), ReqData :: binary()) ->
  RespData :: binary().

-callback user_key_validation_data(UserId :: binary(), ReqData :: binary()) ->
  RespData :: binary().
