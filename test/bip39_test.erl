%%
%% Copyright 2020, Péter Dimitrov <peterdmv@protonmail.com>.
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%

-module(bip39_test).

-include_lib("eunit/include/eunit.hrl").

bip39_test_() ->
    {ok, Vectors0} = file:consult("test/bip39.vectors"),
    Vectors = lists:map(fun prepare_test_vector/1, Vectors0),

    [?_assert(run_test(lists:nth(1, Vectors))),
     ?_assert(run_test(lists:nth(2, Vectors))),
     ?_assert(run_test(lists:nth(3, Vectors))),
     ?_assert(run_test(lists:nth(4, Vectors))),
     ?_assert(run_test(lists:nth(5, Vectors))),
     ?_assert(run_test(lists:nth(6, Vectors))),
     ?_assert(run_test(lists:nth(7, Vectors))),
     ?_assert(run_test(lists:nth(8, Vectors))),
     ?_assert(run_test(lists:nth(9, Vectors))),
     ?_assert(run_test(lists:nth(10, Vectors))),
     ?_assert(run_test(lists:nth(11, Vectors))),
     ?_assert(run_test(lists:nth(12, Vectors))),
     ?_assert(run_test(lists:nth(13, Vectors))),
     ?_assert(run_test(lists:nth(14, Vectors))),
     ?_assert(run_test(lists:nth(15, Vectors))),
     ?_assert(run_test(lists:nth(16, Vectors))),
     ?_assert(run_test(lists:nth(17, Vectors))),
     ?_assert(run_test(lists:nth(18, Vectors))),
     ?_assert(run_test(lists:nth(19, Vectors))),
     ?_assert(run_test(lists:nth(20, Vectors))),
     ?_assert(run_test(lists:nth(21, Vectors))),
     ?_assert(run_test(lists:nth(22, Vectors))),
     ?_assert(run_test(lists:nth(23, Vectors))),
     ?_assert(run_test(lists:nth(24, Vectors)))].

run_test({Entropy, Mnemonic, Seed, _XPrv}) ->
    {ok, Entropy} =:= bip39:mnemonic_to_entropy(Mnemonic)
	andalso Mnemonic =:= bip39:entropy_to_mnemonic(Entropy)
	andalso {ok, Seed} =:= bip39:mnemonic_to_seed(Mnemonic, <<"TREZOR">>).

prepare_test_vector({Entropy, Mnemonic, Seed, XPrv}) ->
    {hexstr2bin(Entropy),
     prepare_mnemonic(Mnemonic),
     hexstr2bin(Seed),
     XPrv %% TODO
    }.

prepare_mnemonic(Mnemonic) ->
    lists:map(fun erlang:list_to_binary/1, string:lexemes(Mnemonic, " ")).

hexstr2bin(S) when is_binary(S) ->
    hexstr2bin(S, <<>>);
hexstr2bin(S) ->
    hexstr2bin(list_to_binary(S), <<>>).
%%
hexstr2bin(<<>>, Acc) ->
    Acc;
hexstr2bin(<<C,T/binary>>, Acc) when C =:= 32;   %% SPACE
                                     C =:= 10;   %% LF
                                     C =:= 13 -> %% CR
    hexstr2bin(T, Acc);
hexstr2bin(<<X,Y,T/binary>>, Acc) ->
    I = hex2int(X) * 16 + hex2int(Y),
    hexstr2bin(T, <<Acc/binary,I>>).

hex2int(C) when $0 =< C, C =< $9 ->
    C - $0;
hex2int(C) when $A =< C, C =< $F ->
    C - $A + 10;
hex2int(C) when $a =< C, C =< $f ->
    C - $a + 10.
