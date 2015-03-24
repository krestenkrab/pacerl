

%% EC Terminology

%% p = 
%% a,b = definition points
%% g = generator {X,Y} point
%% n/q = order (smallest non-negative number, such that n*G = infinity)
%% h/i = cofactor
-record(ec_param, { p,
                    a,
                    b,
                    g,
                    q,
                    h=1,
                    degree}).
