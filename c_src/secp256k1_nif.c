/*
 * Copyright 2020, Péter Dimitrov <peterdmv@protonmail.com>.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "erl_nif.h"

#include "secp256k1.h"
#include <string.h>

static secp256k1_context *ctx = NULL;

static int
load(ErlNifEnv* env, void** priv, ERL_NIF_TERM load_info)
{
  ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
  return 0;
}

static void
unload(ErlNifEnv* env, void* priv)
{
  secp256k1_context_destroy(ctx);
  return;
}

static ERL_NIF_TERM
error_result(ErlNifEnv* env, char* error_msg)
{
  return enif_make_tuple2(env, enif_make_atom(env, "error"),
			  enif_make_string(env, error_msg, ERL_NIF_LATIN1));
}

static ERL_NIF_TERM
ok_result(ErlNifEnv* env, ERL_NIF_TERM *r)
{
    return enif_make_tuple2(env, enif_make_atom(env, "ok"), *r);
}

static int
get_compressed_flag(ErlNifEnv* env, ERL_NIF_TERM arg, int* compressed,
		    size_t* pubkey_len)
{
  char compressed_atom[16];

  if (!enif_get_atom(env, arg, compressed_atom, 16, ERL_NIF_LATIN1)) {
    return 0;
  }

  if (strcmp(compressed_atom, "compressed")  == 0) {
    *pubkey_len = 33;
    *compressed = SECP256K1_EC_COMPRESSED;
    return 1;
  } else if (strcmp(compressed_atom, "uncompressed") == 0) {
    *pubkey_len = 65;
    *compressed = SECP256K1_EC_UNCOMPRESSED;
    return 1;
  }
  return 0;
}

static ERL_NIF_TERM
ec_pubkey_create(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
  ErlNifBinary privkey;
  unsigned char* pubkey;
  ERL_NIF_TERM r;

  if (!enif_inspect_binary(env, argv[0], &privkey)) {
    return enif_make_badarg(env);
  }

  if (privkey.size != 32) {
    return error_result(env, "Invalid private key");
  }

  pubkey = enif_make_new_binary(env, 64, &r);

  if(!secp256k1_ec_pubkey_create(ctx, (secp256k1_pubkey*)pubkey, privkey.data)) {
    return error_result(env, "Failed to create public key");
  } else {
    return ok_result(env, &r);
  }
}

static ERL_NIF_TERM
ec_pubkey_serialize(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
  ERL_NIF_TERM r;
  ErlNifBinary pubkey;
  size_t output_len;
  int compressed;
  unsigned char *output;

  if (!enif_inspect_binary(env, argv[0], &pubkey)) {
    return enif_make_badarg(env);
  }

  if (pubkey.size != 64) {
    return error_result(env, "Invalid public key");
  }

  if (!get_compressed_flag(env, argv[1], &compressed, &output_len)) {
    return error_result(env, "Compression flag invalid");
  }

  output = enif_make_new_binary(env, output_len, &r);

  if(secp256k1_ec_pubkey_serialize(ctx,
				   output,
				   &output_len,
				   (const secp256k1_pubkey*)&pubkey,
				   compressed)) {
    return ok_result(env, &r);
  } else {
    return error_result(env, "Failed to serialize public key");
  }
}

static ErlNifFunc nif_funcs[] =
  {
   {"ec_pubkey_create", 1, ec_pubkey_create},
   {"ec_pubkey_serialize", 2, ec_pubkey_serialize}
  };

ERL_NIF_INIT(secp256k1, nif_funcs, &load, NULL, NULL, &unload);
