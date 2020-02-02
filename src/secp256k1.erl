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

-module(secp256k1).

-export([ec_pubkey_create/1]).

-on_load(init/0).

-define(APPNAME, ewallet).
-define(LIBNAME, ewallet).

ec_pubkey_create(_) ->
    not_loaded(?LINE).

init() ->
    SoName = case code:priv_dir(?APPNAME) of
		 {error, bad_name} ->
		     case filelib:is_dir(filename:join(["..", priv])) of
			 true ->
			     filename:join(["..", priv, ?LIBNAME]);
			 _ ->
			     filename:join([priv, ?LIBNAME])
		     end;
		 Dir ->
		     filename:join(Dir, ?LIBNAME)
	     end,
    erlang:load_nif(SoName, 0).

not_loaded(Line) ->
    erlang:nif_error({not_loaded, [{module, ?MODULE}, {line, Line}]}).
