-module(pace).

%% Password Authenticated Connection Establishment (PACE) example

-export([pace_client/4, test/0]).

-include("ec.hrl").

-define(CURVE, brainpoolP320r1).
-define(BITS, 320).
-define(HASH, sha256).
-define(ENC,  aes_cbc256).

%-define(CURVE, brainpoolP256r1).
%-define(BITS, 256).
%-define(HASH, sha256).
%-define(ENC,  aes_cbc256).

%-define(CURVE, secp192r1).
%-define(BITS, 192).
%-define(HASH, sha256).
%-define(ENC,  aes_cbc128).


%% crypto functions

kdf_pi(PIN,Salt) ->
    Key = pbkdf2:pbkdf2(?HASH, PIN, Salt, 1024),
%    true = (?BITS =< bit_size(Key)),
    Bytes = keybits(?ENC) div 8,
    <<OutKey:Bytes/binary, _/binary>> = Key,
    OutKey.

kdf_mac(Point={_,_}) ->
    Bin = point2bin(Point),
    crypto:hash(?HASH, Bin).

mac(Key, Point={_,_}) when is_binary(Key) ->
    crypto:hmac(?HASH, Key, point2bin(Point));
mac(Key, I) when is_binary(Key), I>0 ->
    crypto:hmac(?HASH, Key, uint2bin(I)).

keybits(aes_cbc128) ->
    128;
keybits(aes_cbc256) ->
    256.

enc(Key, I) when I>0 ->
    IV = crypto:rand_bytes(16),
    PlainText = uint2bin32(I), % must be multiple of 32 bytes
    Encoded = crypto:block_encrypt(?ENC, Key, IV, PlainText),
    << IV/binary, Encoded/binary>>.

dec(Key, <<IV:16/binary, CipherText/binary>>) ->
    Bin = crypto:block_decrypt(?ENC, Key, IV, CipherText),
    bin2uint(Bin).


%% PICC (Proximity Integrated Circuit Card) plays the server role

pace_server(PIN, PKcc, PKapp, Dom=#ec_param{ g=G }) ->

    ClientPID = receive
                 {get_param, CL} ->
                     CL ! Dom,
                     CL
             after 1000 ->
                     exit(wait_x1)
             end,

    S = ec:random(Dom),
    Ypriv = ec:random(Dom),
    SKserver = ec:random(Dom),


    %% 1.a
    Salt = <<"1234">>,
    K_pi = kdf_pi([PIN, PKcc, PKapp], Salt),

    %% 1.b
    Z = enc(K_pi, S),
    ClientPID ! {z, Salt, Z},


    %% 1.c
    Ypub = ec:mul(G, Ypriv, Dom),
    ClientPID ! {y_pub, Ypub},

    H = receive
            {x_pub, Xpub} ->
                %% 1.d
                ec:mul(Xpub, Ypriv, Dom)
        after 1000 ->
                exit(wait_x2)
        end,

    %% 1.e
    Gprime = ec:add( ec:mul(G, S, Dom),  H, Dom),

    %% 1.f
    PKserver = ec:mul(Gprime, SKserver, Dom),

    ClientPID ! {pk_server, PKserver},
    PKclient = receive
                   {pk_client, PK} -> PK
               after 1000 ->
                       exit(wait_x3)
               end,

    %% 1.g
    K = ec:mul(PKclient, SKserver, Dom),

    %% 1.i
    Kmac = kdf_mac(K),

    %% 1.j
    Tserver = mac(Kmac, PKclient),
    ClientPID ! {t_server, Tserver},

    Tclient = mac(Kmac, PKserver),

    io:format("SERVER.K      = ~p~n", [K]),

    receive
        {t_client, Tclient} ->
            io:format("server success~n", []);
        {t_client, _} ->
            io:format("server failure~n", [])
    after 1000 ->
            exit(wait_x4)
    end,

    ok.


%% CLIENT (Proximity Coupling Device) plays the client role

pace_client(PIN, PKcc, PKapp, ServerPID) ->

    ServerPID ! {get_param, self()},
    receive
        Dom=#ec_param{g=G} ->
            ok
    after 2000 ->
            G = undefined,
            Dom=undefined,
            exit(wait_1)
    end,

    Xpriv = ec:random(Dom),
    SKclient = ec:random(Dom),

    %% 2.a

    %% 2.b
    S = receive
            {z, Salt, Z} ->
                K_pi = kdf_pi([PIN, PKcc, PKapp], Salt),
                dec(K_pi, Z)
        after 2000 ->
                exit(wait_2)
        end,

    %% 2.c
    Xpub = ec:mul(G, Xpriv, Dom),
    ServerPID ! {x_pub, Xpub},
    H = receive
            {y_pub, Ypub} ->
                %% 2.d
                ec:mul(Ypub, Xpriv, Dom)
        after 2000 ->
                exit(wait_3)
        end,

    %% 2.e
    Gprime = ec:add(ec:mul(G, S, Dom), H, Dom),

    %% 2.f
    PKclient = ec:mul(Gprime, SKclient, Dom),
    ServerPID ! {pk_client, PKclient},
    PKserver = receive {pk_server, PK} -> PK
               after 2000 -> exit(wait_4)
               end,

    %% 2.g
    K = ec:mul(PKserver, SKclient, Dom),

    %% 2.i
    Kmac = kdf_mac(K),

    %% 2.j
    Tclient = mac(Kmac, PKserver),
    ServerPID ! {t_client, Tclient},

    Tserver = mac(Kmac, PKclient),

    io:format("CLIENT.K      = ~p~n", [K]),

    receive
        {t_server, Tserver} ->
            io:format("client success~n", []),
            ok;
        {t_server, _} ->
            {error, token_mismatch}
    after 1000 ->
            exit(wait_5)
    end.

%%
%% Utility to encode/decode integer as big-endian bytestring
%%

%% Encode as "uncompressed" Fp point
point2bin({X,Y}) ->
    <<4, X:?BITS/unsigned, Y:?BITS/unsigned>>.

%% produce a 32-byte multiple encoding of an unsigned number
uint2bin32(N) ->
    Bin = uint2bin(N),
    case byte_size(Bin) rem 32 of
        0 -> Bin;
        X -> Missin = 32-X, << 0:Missin/unit:8, Bin/binary>>
    end.

uint2bin(0) ->
    <<>>;
uint2bin(N) when is_integer(N) ->
    Prefix = uint2bin( N bsr 8 ),
    Low = N band 255,
    << Prefix/binary, Low:8 >>.

bin2uint(Bin) ->
    bin2uint(0, Bin).

bin2uint(N, <<>>) ->
    N;
bin2uint(N, <<V:8, Rest/binary>>) ->
    bin2uint((N bsl 8) bor V, Rest).


test() ->
    crypto:start(),

    P256 = ec:get_curve(?CURVE),

    ServerPID = spawn_link(fun() -> pace_server(<<"1234">>, <<"foo">>, <<"bar">>, P256) end),
    pace_client(<<"1234">>, <<"foo">>, <<"bar">>, ServerPID).




