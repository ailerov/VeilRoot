// Copyright (c) 2026, The VeilRoot Project
// SPDX-License-Identifier: BSD-3-Clause

#include "bip340.h"
#include <secp256k1.h>
#include <secp256k1_schnorrsig.h>
#include <cstring>

namespace bip340 {

static secp256k1_context* get_context(int flags) {
    static secp256k1_context* ctx = secp256k1_context_create(flags);
    return ctx;
}

bool sign(const uint8_t* private_key, const uint8_t* message, uint8_t* signature_out) {
    secp256k1_context* ctx = get_context(SECP256K1_CONTEXT_SIGN);
    secp256k1_keypair keypair;
    if (!secp256k1_keypair_create(ctx, &keypair, private_key)) {
        return false;
    }
    return secp256k1_schnorrsig_sign32(ctx, signature_out, message, &keypair, nullptr) == 1;
}

bool verify(const uint8_t* public_key, const uint8_t* message, const uint8_t* signature) {
    secp256k1_context* ctx = get_context(SECP256K1_CONTEXT_VERIFY);
    secp256k1_xonly_pubkey xonly_pubkey;
    // The 33‑byte compressed key has prefix byte 0x02 or 0x03; skip it.
    if (!secp256k1_xonly_pubkey_parse(ctx, &xonly_pubkey, public_key + 1)) {
        return false;
    }
    return secp256k1_schnorrsig_verify(ctx, signature, message, 32, &xonly_pubkey) == 1;
}

std::string pubkey_to_hex(const uint8_t* pubkey) {
    char hex[67] = {0};
    for (int i = 0; i < 33; ++i)
        sprintf(hex + i*2, "%02x", pubkey[i]);
    return std::string(hex);
}

} // namespace bip340