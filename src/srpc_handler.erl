-module(srpc_handler).

-author("paul@knoxen.com").

-callback put(Id :: binary(), Value :: term(), Cache :: atom) ->
  ok | {error, Reason :: string()}.

-callback get(Id :: binary(), Cache :: atom) ->
  {ok, Value :: term()} | undefined.

-callback delete(Id :: binary(), Cache :: atom) ->
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
