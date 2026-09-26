// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "gtest/gtest.h"
#include "governance/vote_serialization.h"
#include "governance/voting_weight.h"
#include "crypto/crypto.h"
#include "crypto/hash.h"
#include <cstring>

using namespace cryptonote;
using namespace governance;

TEST(vote_serialization, basic_serialization) {
    // Create a test vote
    VoteData vote;
    crypto::hash proposal_id;

    // Initialize with known values for testing
    memset(proposal_id.data, 0x12, sizeof(proposal_id.data));

    vote.proposal_id = proposal_id;
    vote.choice = VoteChoice::YES;
    vote.timestamp = 1234567890;
    vote.weight = 1000000;

    // Generate test keys using proper crypto functions
    crypto::secret_key secret_key;
    crypto::public_key public_key;

    // Use the proper crypto functions to generate keys
    crypto::generate_keys(public_key, secret_key);

    vote.voter_key = public_key;

    // Test string serialization
    std::string buffer;
    ASSERT_TRUE(serialize_vote_data(vote, buffer));

    // Deserialize and verify
    VoteData vote2;
    ASSERT_TRUE(deserialize_vote_data(buffer, vote2));

    EXPECT_EQ(vote.proposal_id, vote2.proposal_id);
    EXPECT_EQ(vote.choice, vote2.choice);
    EXPECT_EQ(vote.timestamp, vote2.timestamp);
    EXPECT_EQ(vote.weight, vote2.weight);
    EXPECT_EQ(vote.voter_key, vote2.voter_key);
}

TEST(vote_serialization, vector_serialization) {
    // Create a test vote
    VoteData vote;
    crypto::hash proposal_id;

    // Initialize with known values for testing
    memset(proposal_id.data, 0x56, sizeof(proposal_id.data));

    vote.proposal_id = proposal_id;
    vote.choice = VoteChoice::NO;
    vote.timestamp = 987654321;
    vote.weight = 500000;

    // Generate test keys using proper crypto functions
    crypto::secret_key secret_key;
    crypto::public_key public_key;

    // Use the proper crypto functions to generate keys
    crypto::generate_keys(public_key, secret_key);

    vote.voter_key = public_key;

    // Test vector serialization
    std::vector<uint8_t> buffer;
    ASSERT_TRUE(serialize_vote_data(vote, buffer));

    // Deserialize and verify
    VoteData vote2;
    ASSERT_TRUE(deserialize_vote_data(buffer, vote2));

    EXPECT_EQ(vote.proposal_id, vote2.proposal_id);
    EXPECT_EQ(vote.choice, vote2.choice);
    EXPECT_EQ(vote.timestamp, vote2.timestamp);
    EXPECT_EQ(vote.weight, vote2.weight);
    EXPECT_EQ(vote.voter_key, vote2.voter_key);
}

TEST(vote_serialization, signing_and_verification) {
    // Create a test vote
    VoteData vote;
    crypto::hash proposal_id;

    // Initialize with known values for testing
    memset(proposal_id.data, 0x9A, sizeof(proposal_id.data));

    vote.proposal_id = proposal_id;
    vote.choice = VoteChoice::ABSTAIN;
    vote.timestamp = 1111111111;
    vote.weight = 750000;

    // Generate test keys using proper crypto functions
    crypto::secret_key secret_key;
    crypto::public_key public_key;

    // Use the proper crypto functions to generate keys
    crypto::generate_keys(public_key, secret_key);

    vote.voter_key = public_key;

    // Sign the vote
    ASSERT_TRUE(sign_vote(vote, secret_key));

    // Verify the signature
    ASSERT_TRUE(verify_vote_signature(vote));

    // Test that invalid signature fails verification
    // Modify the vote to make signature invalid
    vote.choice = VoteChoice::YES;
    ASSERT_FALSE(verify_vote_signature(vote));
}

// Test different vote choices
TEST(vote_serialization, vote_choices) {
    VoteData vote;
    crypto::hash proposal_id;

    // Initialize with known values for testing
    memset(proposal_id.data, 0xDE, sizeof(proposal_id.data));
    vote.proposal_id = proposal_id;
    vote.timestamp = 1234567890;
    vote.weight = 1000000;

    // Generate test keys using proper crypto functions
    crypto::secret_key secret_key;
    crypto::public_key public_key;

    // Use the proper crypto functions to generate keys
    crypto::generate_keys(public_key, secret_key);
    vote.voter_key = public_key;

    // Test all vote choices
    vote.choice = VoteChoice::YES;
    std::string buffer;
    ASSERT_TRUE(serialize_vote_data(vote, buffer));
    VoteData vote2;
    ASSERT_TRUE(deserialize_vote_data(buffer, vote2));
    EXPECT_EQ(vote2.choice, VoteChoice::YES);

    vote.choice = VoteChoice::NO;
    ASSERT_TRUE(serialize_vote_data(vote, buffer));
    ASSERT_TRUE(deserialize_vote_data(buffer, vote2));
    EXPECT_EQ(vote2.choice, VoteChoice::NO);

    vote.choice = VoteChoice::ABSTAIN;
    ASSERT_TRUE(serialize_vote_data(vote, buffer));
    ASSERT_TRUE(deserialize_vote_data(buffer, vote2));
    EXPECT_EQ(vote2.choice, VoteChoice::ABSTAIN);
}