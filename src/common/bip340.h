// Copyright (c) 2026, The VeilRoot Project
// SPDX-License-Identifier: BSD-3-Clause

#pragma once

#include <string>
#include <cstdint>

namespace bip340 {

// Sign a 32‑byte message (e.g., event ID) with a 32‑byte private key.
// Returns true on success, fills signature (64 bytes: r || s).
bool sign(const uint8_t* private_key, const uint8_t* message, uint8_t* signature_out);

// Verify a 64‑byte signature against a 32‑byte message and a 33‑byte compressed public key.
bool verify(const uint8_t* public_key, const uint8_t* message, const uint8_t* signature);

// Convert a 33‑byte compressed public key to hex string (optional, for logging).
std::string pubkey_to_hex(const uint8_t* pubkey);

} // namespace bip340