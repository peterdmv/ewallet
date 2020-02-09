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

%%%-------------------------------------------------------------------
%% @doc Implementation of Bitcoin BIP32:
%%      Hierarchical Deterministic Wallets
%% @end
%%%-------------------------------------------------------------------

-module(bip32).

-export([point/1,
	 ser_32/1,
	 ser_256/1,
	 ser_p/1]).

point(P) ->
    secp256k1:ec_pubkey_create(P).

ser_32(I) ->
    <<I:4/big-unsigned-integer-unit:8>>.

ser_256(I) ->
    <<I:32/big-integer-unit:8>>.

ser_p(P) ->
    secp256k1:ec_pubkey_serialize(P, compressed).
