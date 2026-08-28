// Copyright (c) 2014-2022, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "hardforks.h"
#include "cryptonote_config.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "blockchain.hardforks"

const hardfork_t mainnet_hard_forks[] = {
  // version 1 from the start
  { 1, 1, 0, 1780743998 },
  // version 16 (treasury fork) at height 22000
  { HF_VERSION_VNS_TREASURY, 22000, 0, 1780743998 + 22000 * 120 },
  // version 6 (ring size 2) from height 50000
  { HF_VERSION_MIN_MIXIN_4, 50000, 0, 1780743998 + 50000 * 120 },
  // version 7 (ring size 3) from height 100000
  { HF_VERSION_MIN_MIXIN_6, 100000, 0, 1780743998 + 100000 * 120 },
  // version 8 (ring size 5) from height 200000
  { HF_VERSION_MIN_MIXIN_10, 200000, 0, 1780743998 + 200000 * 120 },
  // version 15 (ring size 7) from height 400000
  { HF_VERSION_MIN_MIXIN_15, 400000, 0, 1780743998 + 400000 * 120 },
  // version 15 already; bulletproofs plus from height 1600000
  { HF_VERSION_BULLETPROOF_PLUS, 1600000, 0, 1780743998 + 1600000 * 120 },
};
const size_t num_mainnet_hard_forks = sizeof(mainnet_hard_forks) / sizeof(mainnet_hard_forks[0]);

const uint64_t mainnet_hard_fork_version_1_till = 49999;   // version 1 is valid up to block 49999
const uint64_t testnet_hard_fork_version_1_till = 0;

const hardfork_t testnet_hard_forks[] = {};
const size_t num_testnet_hard_forks = 0;

const hardfork_t stagenet_hard_forks[] = {};
const size_t num_stagenet_hard_forks = 0;
