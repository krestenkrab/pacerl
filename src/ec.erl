-module(ec).

-include("ec.hrl").

-export([random/1, add/3,double/2,mul/3,test/0,modinv/2,modpow/3,get_curve/1]).

%% @doc
%% Generate a random scalar value in the domain [1..q-1] of the given curve
random(Dom=#ec_param{ q=Q, degree=BitSize }) ->
    <<Value:BitSize>> = crypto:strong_rand_bytes(BitSize div 8),
    case Value >= (Q-1) orelse Value =:= 0 of
        true -> random(Dom);  %% need to pick a better number
        false -> Value
    end.

add(Point,Point,Dom) ->
    double(Point,Dom);
add(infinity,Point,_) ->
    Point;
add(Point,infinity,_) ->
    Point;
add({Rx,Ry}, {Sx,Sy}, #ec_param{ p=P }) when Rx /= Sx ->
    Slope = moddiv( Ry-Sy, Rx-Sx, P ),
    Xout  = mod( modpow(Slope, 2, P) - Rx - Sx, P),
    Yout  = mod( P - Sy + Slope * (Sx-Xout), P ),
    {Xout, Yout}.


double(infinity, _) ->
    infinity;
double({Rx,Ry}, #ec_param{ a=A, p=P }) ->
    Slope = (modpow(Rx,2,P) * 3 + A) * modinv(2 * Ry, P),
    Xout  = mod( modpow(Slope, 2, P) - (Rx*2), P),
    Yout  = mod( -Ry + Slope * (Rx-Xout) , P),
    {Xout,Yout}.

mul(infinity, _, _) ->
    infinity;
mul(_, 0, _) ->
    infinity;
mul(P, N, Dom) when N>0 ->
    case N band 1 of
        1 -> add(P, mul(P, N-1, Dom), Dom);
        0 -> mul(double(P,Dom), N bsr 1, Dom)
    end.

%%% UTILITY %%%

countbits(0,Acc) -> Acc;
countbits(N,Acc) -> countbits(N bsr 8, Acc+8). 

mod(N,V) when N >= 0 ->
    N rem V;
mod(N,V) when N < 0 ->
    V + (N rem V).

modpow(A,B,Mod) ->
    modpow(1,A,B,Mod).

modpow(X,_,0,_) ->
    X;
modpow(1,Y,B,Mod) ->            % specialized for X=1
    X2 = case (B band 1) of
             1 -> Y;
             0 -> 1
         end,
    Y2 = (Y*Y) rem Mod,
    modpow(X2, Y2, B bsr 1, Mod);
modpow(X,Y,B,Mod) ->
    X2 = case (B band 1) of
             1 -> (X*Y) rem Mod;
             0 -> X
         end,
    Y2 = (Y*Y) rem Mod,
    modpow(X2, Y2, B bsr 1, Mod).

%%
%% Inspired by http://www.johannes-bauer.com/compsci/ecc/
%% eea = "extended euclidian algorithm"
%%
modinv(A,B) when B>0, is_integer(A) ->
    case eea(A,B,1,0,0,1) of
        {_GCD, _BezM, BezN} when BezN < 0 ->
            B+BezN;
        {_GCD, _BezM, BezN} when BezN >= 0 ->
            BezN
    end.

eea(A,0,_S,_T,U,V) ->
    {A,U,V};
eea(A,B,S,T,U,V) when A < 0 ->
    eea(mod(A,B), B, S, T, U, V);
eea(A,B,S,T,U,V) ->
    Q = A div B,
    R = A rem B,
    Snew = U - Q*S,
    Tnew = V - Q*T,
    eea(B, R, Snew, Tnew, S, T).

moddiv(A,B,M) ->
    mod(A * modinv(B,M), M).

bin2uint(Bin) ->
    Size = bit_size(Bin),
    << Result:Size/unsigned >> = Bin,
    Result.

get_curve(Name) ->
    %% this code might be R17 specific, as it depends on the internal
    %% representation of named curves.
    {{prime_field, PBin},
     {ABin,BBin,_},
     GBin, %
     QBin, %ok
     HBin} %ok
        = crypto:ec_curve(Name),

    %% decode base point
    Len = byte_size(GBin),
    Bits = ((Len-1) div 2) * 8,
    <<4, GX:Bits, GY:Bits >> = GBin,

    #ec_param{
      p = bin2uint(PBin),
      g = { GX, GY },
      a = bin2uint(ABin),
      b = bin2uint(BBin),
      q = bin2uint(QBin),
      h = bin2uint(HBin),
      degree=Bits       %% add bit-size, so we can generate
                          %% random numbers with proper size.
 }.

test() ->

    %% Known test data from the NIST report

    P192 = ec:get_curve(secp192r1),

    S = { 16#d458e7d127ae671b0c330266d246769353a012073e97acf8,
          16#325930500d851f336bddc050cf7fb11b5673a1645086df3b },
    T = { 16#f22c4395213e9ebe67ddecdd87fdbd01be16fb059b9753a4,
          16#264424096af2b3597796db48f8dfb41fa9cecc97691a9c79 },

    {Rx,_Ry} = add(S,T,P192),

    Rx = 16#48e1e4096b9b8e5ca9d0f1f077b8abf58e843894de4d0290,

    R2 = double(S,P192),
    { 16#30c5bc6b8c7da25354b373dc14dd8a0eba42d25a3f6e6962,
      16#0dde14bc4249a721c407aedbf011e2ddbbcb2968c9d889cf } = R2,

    D = 16#a78a236d60baec0c5dd41b33a542463a8255391af64c74ee,

    R3 = mul(S,D,P192),
    Test =
    { 16#1faee4205a4f669d2d0a8f25e3bcec9a62a6952965bf6d31,
      16#5ff2cdfa508a2581892367087c696f179e7a4d7e8260fb06},

    R3 = Test,

    ok.

