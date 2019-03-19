%%==================================================================================================
%%
%%  SRPC Types
%%
%%  Shared by srpc_lib and srpc_srv.
%%
%%==================================================================================================
-type ok_binary()   :: {ok, binary()}.
-type error_msg()   :: {error, binary()}.
-type invalid_msg() :: {invalid, binary()}.

-type id() :: binary().

-type data_in() :: <<_:_*8>>.

-type nonced_data() :: {ok, {binary(), binary()}}.

-type password()  :: binary().
-type salt()      :: binary().
-type hash()      :: binary().

-type srp_key()      :: binary().
-type srp_pub_key()  :: srp_key().
-type srp_priv_key() :: srp_key().
-type srp_key_pair() :: {srp_pub_key(), srp_priv_key()}.

-type aes_block() :: <<_:128>>.
-type sym_key()   :: <<_:128>> | <<_:192>> | <<_:256>>.
-type hmac_key()  :: <<_:256>>.

-type origin() :: requester | responder.

-type sym_alg()  :: aes128 | aes192 | aes256.
-type sym_mode() :: aes_cbc256.
-type sha_alg()  :: sha256 | sha384 | sha512.

-type sec_algs() :: #{sym_alg  => sym_alg(),
                      sym_mode => sym_mode(),
                      sha_alg  => sha_alg()}.

-type sec_opt() :: <<_:32>>.

-type srp_g() :: binary().
-type srp_N() :: binary().
-type srp_group() :: {srp_g(), srp_N()}.

-type srp_info() :: #{password   => password(),
                      kdf_salt   => salt(),
                      kdf_rounds => integer(),
                      srp_salt   => salt()}.
-type srp_value() :: binary().

-type srp_registration() :: #{user_id   => id(),
                              srp_info  => srp_info(),
                              srp_value => srp_value()
                             }.

-type srpc_shared_config() :: #{type      => byte(),
                                srpc_id   => id(),
                                sec_opt   => sec_opt(),
                                srp_group => srp_group()
                               }.

-type srpc_server_config() :: #{type      => byte(),
                                srpc_id   => id(),
                                sec_opt   => sec_opt(),
                                srp_group => srp_group(),
                                srp_value => srp_value()
                               }.

-type srpc_client_config() :: #{type      => byte(),
                                srpc_id   => id(),
                                sec_opt   => sec_opt(),
                                srp_group => srp_group(),
                                srp_info  => srp_info()
                               }.

-type srpc_config()      :: srpc_server_config() | srpc_client_config().
-type ok_server_config() :: {ok, srpc_server_config()}.
-type ok_client_config() :: {ok, srpc_client_config()}.
-type ok_config()        :: {ok, srpc_config()}.

-type exch_info() :: #{pub_key     => srp_pub_key(),
                       key_pair    => srp_key_pair(),
                       secret_hash => binary()}.

-type conn_keys() :: #{req_sym_key   => sym_key(),
                       req_hmac_key  => hmac_key(),
                       resp_sym_key  => sym_key(),
                       resp_hmac_key => hmac_key()}.

-type conn_type() :: lib | user.

-type conn() :: #{type      => conn_type(),
                  conn_id   => id(),
                  entity_id => id(),
                  exch_info => exch_info(),
                  config    => srpc_client_config() | srpc_server_config(),
                  msg_hdr   => binary(),
                  sec_algs  => sec_algs(),
                  keys      => conn_keys()
                 }.

-type ok_conn() :: {ok, conn()}.

