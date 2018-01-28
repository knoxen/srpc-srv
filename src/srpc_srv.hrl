%%==================================================================================================
%%
%%  Constants
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%%  Version of header format
%%--------------------------------------------------------------------------------------------------
-define(HDR_VSN, 1).

%%--------------------------------------------------------------------------------------------------
%%  Bits sizes
%%--------------------------------------------------------------------------------------------------
-define(HDR_BITS,    8).
-define(TIME_BITS,  32).
-define(NONCE_BITS,  8).

%%--------------------------------------------------------------------------------------------------
%%  Registration codes
%%--------------------------------------------------------------------------------------------------
-define(SRPC_REGISTRATION_CREATE,      1).
-define(SRPC_REGISTRATION_UPDATE,      2).
-define(SRPC_REGISTRATION_OK,         10).
-define(SRPC_REGISTRATION_DUP,        11).
-define(SRPC_REGISTRATION_NOT_FOUND,  12).
-define(SRPC_REGISTRATION_ERROR,     255).

%%==================================================================================================
%%
%%  Types
%%
%%==================================================================================================
-type ok_response()  :: {ok, binary()}.
-type error_msg()    :: {error, binary()}.
-type invalid_msg()  :: {invalid, binary()}.

-type data_in()      :: <<_:_*8>>.

-type conn_id()      :: binary().
-type user_id()      :: binary().

-type exch_key()      :: binary().
-type exch_key_pair() :: {exch_key(), exch_key()}.
-type aes_block()     :: <<_:128>>.
-type sym_key()       :: <<_:128>> | <<_:192>> | <<_:256>>.
-type hmac_key()      :: <<_:256>>.
-type sym_alg()       :: aes128 | aes192 | aes256.
-type sha_alg()       :: sha256 | sha384 | sha512.
-type conn_info()     :: #{conn_id         => conn_id()
                          ,exch_public_key => exch_key()
                          ,exch_key_pair   => exch_key_pair()
                          ,sym_alg         => sym_alg()
                          ,sha_alg         => sha_alg()
                          ,req_sym_key     => sym_key()
                          ,resp_sym_key    => sym_key()
                          ,hmac_key        => hmac_key()
                          }.

-type registration() :: #{user_id  => binary()
                          ,kdf_salt => binary()
                          ,srp_salt => binary()
                          ,verifier => binary()
                          }.

-type origin()      :: origin_requester | origin_responder.
-type nonced_data() :: {ok, {binary(), binary()}}.
