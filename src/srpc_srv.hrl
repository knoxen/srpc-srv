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
-type ok_response() :: {ok, binary()}.
-type error_msg()   :: {error, binary()}.
-type invalid_msg() :: {invalid, binary()}.
-type data_in()     :: <<_:_*8>>.
-type srpc_id()     :: binary().
-type conn_id()     :: binary().
-type user_id()     :: binary().
-type bin_32()      :: <<_:32>>.
-type salt()        :: binary().
-type exch_key()    :: binary().
-type exch_keys()   :: {exch_key(), exch_key()}.
-type aes_block()   :: <<_:128>>.
-type sym_key()     :: <<_:128>> | <<_:192>> | <<_:256>>.
-type hmac_key()    :: <<_:256>>.
-type sym_alg()     :: aes128 | aes192 | aes256.
-type sha_alg()     :: sha256 | sha384 | sha512.
-type origin()      :: requester | responder.

-type srpc_shared_config() :: #{srpc_id   => srpc_id(),
                                sec_opt   => bin_32(),
                                generator => binary(),
                                modulus   => binary()
                               }.

-type srpc_server_config() :: #{srpc_id   => srpc_id(),
                                sec_opt   => bin_32(),
                                generator => binary(),
                                modulus   => binary(),
                                srp_value => binary()
                               }.

-type srpc_client_config() :: #{srpc_id    => srpc_id(),
                                sec_opt    => bin_32(),
                                generator  => binary(),
                                modulus    => binary(),
                                password   => binary(),
                                kdf_salt   => salt(),
                                kdf_rounds => bin_32(),
                                srp_salt   => salt()
                               }.

-type conn() :: #{conn_id       => conn_id(),
                  exch_pubkey   => exch_key(),
                  exch_keys     => exch_keys(),
                  entity_id     => binary(),
                  config        => srpc_client_config() | srpc_server_config(),
                  sym_alg       => sym_alg(),
                  sha_alg       => sha_alg(),
                  req_sym_key   => sym_key(),
                  req_hmac_key  => hmac_key(),
                  resp_sym_key  => sym_key(),
                  resp_hmac_key => hmac_key()
                 }.

-type registration() :: #{user_id    => binary(),
                          kdf_salt   => binary(),
                          kdf_rounds => bin_32(),
                          srp_salt   => binary(),
                          srp_value  => binary()
                         }.
-type nonced_data() :: {ok, {binary(), binary()}}.

