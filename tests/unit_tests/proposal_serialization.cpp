// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "gtest/gtest.h"
#include "governance/proposal_serialization.h"
#include "crypto/crypto.h"
#include "crypto/hash.h"
#include <cstring>

using namespace cryptonote;
using namespace governance;

TEST(proposal_serialization, basic_serialization) {
    // Create a test proposal
    ProposalData proposal;
    crypto::hash proposal_id;

    // Initialize with known values for testing
    memset(proposal_id.data, 0x12, sizeof(proposal_id.data));

    proposal.proposal_id = proposal_id;
    proposal.title = "Test Proposal Title";
    proposal.description = "This is a test proposal description for demonstration purposes.";
    proposal.type = "governance";
    proposal.voting_start_time = 1234567890;
    proposal.voting_end_time = 1234567890 + 86400; // 1 day later

    // Generate test keys using proper crypto functions
    crypto::secret_key secret_key;
    crypto::public_key public_key;

    // Use the proper crypto functions to generate keys
    crypto::generate_keys(public_key, secret_key);

    proposal.author_key = public_key;

    // Test string serialization
    std::string buffer;
    ASSERT_TRUE(serialize_proposal_data(proposal, buffer));

    // Deserialize and verify
    ProposalData proposal2;
    ASSERT_TRUE(deserialize_proposal_data(buffer, proposal2));

    EXPECT_EQ(proposal.proposal_id, proposal2.proposal_id);
    EXPECT_EQ(proposal.title, proposal2.title);
    EXPECT_EQ(proposal.description, proposal2.description);
    EXPECT_EQ(proposal.type, proposal2.type);
    EXPECT_EQ(proposal.voting_start_time, proposal2.voting_start_time);
    EXPECT_EQ(proposal.voting_end_time, proposal2.voting_end_time);
    EXPECT_EQ(proposal.author_key, proposal2.author_key);
}

TEST(proposal_serialization, vector_serialization) {
    // Create a test proposal
    ProposalData proposal;
    crypto::hash proposal_id;

    // Initialize with known values for testing
    memset(proposal_id.data, 0x56, sizeof(proposal_id.data));

    proposal.proposal_id = proposal_id;
    proposal.title = "Vector Serialization Test";
    proposal.description = "Testing vector serialization functionality.";
    proposal.type = "technical";
    proposal.voting_start_time = 987654321;
    proposal.voting_end_time = 987654321 + 86400; // 1 day later

    // Generate test keys using proper crypto functions
    crypto::secret_key secret_key;
    crypto::public_key public_key;

    // Use the proper crypto functions to generate keys
    crypto::generate_keys(public_key, secret_key);

    proposal.author_key = public_key;

    // Test vector serialization
    std::vector<uint8_t> buffer;
    ASSERT_TRUE(serialize_proposal_data(proposal, buffer));

    // Deserialize and verify
    ProposalData proposal2;
    ASSERT_TRUE(deserialize_proposal_data(buffer, proposal2));

    EXPECT_EQ(proposal.proposal_id, proposal2.proposal_id);
    EXPECT_EQ(proposal.title, proposal2.title);
    EXPECT_EQ(proposal.description, proposal2.description);
    EXPECT_EQ(proposal.type, proposal2.type);
    EXPECT_EQ(proposal.voting_start_time, proposal2.voting_start_time);
    EXPECT_EQ(proposal.voting_end_time, proposal2.voting_end_time);
    EXPECT_EQ(proposal.author_key, proposal2.author_key);
}

TEST(proposal_serialization, signing_and_verification) {
    // Create a test proposal
    ProposalData proposal;
    crypto::hash proposal_id;

    // Initialize with known values for testing
    memset(proposal_id.data, 0x9A, sizeof(proposal_id.data));

    proposal.proposal_id = proposal_id;
    proposal.title = "Signed Proposal Test";
    proposal.description = "Testing signature verification functionality.";
    proposal.type = "marketing";
    proposal.voting_start_time = 1111111111;
    proposal.voting_end_time = 1111111111 + 86400; // 1 day later

    // Generate test keys using proper crypto functions
    crypto::secret_key secret_key;
    crypto::public_key public_key;

    // Use the proper crypto functions to generate keys
    crypto::generate_keys(public_key, secret_key);

    proposal.author_key = public_key;

    // Sign the proposal
    ASSERT_TRUE(sign_proposal(proposal, secret_key));

    // Verify the signature
    ASSERT_TRUE(verify_proposal_signature(proposal));

    // Test that invalid signature fails verification
    // Modify the proposal to make signature invalid
    proposal.title = "Modified Title";
    ASSERT_FALSE(verify_proposal_signature(proposal));
}

TEST(proposal_serialization, edge_cases) {
    // Test with empty strings
    ProposalData proposal;
    crypto::hash proposal_id;
    memset(proposal_id.data, 0xDE, sizeof(proposal_id.data));

    proposal.proposal_id = proposal_id;
    proposal.title = "";
    proposal.description = "";
    proposal.type = "";
    proposal.voting_start_time = 0;
    proposal.voting_end_time = 0;

    // Generate test keys
    crypto::secret_key secret_key;
    crypto::public_key public_key;
    crypto::generate_keys(public_key, secret_key);
    proposal.author_key = public_key;

    // Test serialization with empty strings
    std::string buffer;
    ASSERT_TRUE(serialize_proposal_data(proposal, buffer));

    ProposalData proposal2;
    ASSERT_TRUE(deserialize_proposal_data(buffer, proposal2));

    EXPECT_EQ(proposal.proposal_id, proposal2.proposal_id);
    EXPECT_EQ(proposal.title, proposal2.title);
    EXPECT_EQ(proposal.description, proposal2.description);
    EXPECT_EQ(proposal.type, proposal2.type);
    EXPECT_EQ(proposal.voting_start_time, proposal2.voting_start_time);
    EXPECT_EQ(proposal.voting_end_time, proposal2.voting_end_time);
    EXPECT_EQ(proposal.author_key, proposal2.author_key);
}