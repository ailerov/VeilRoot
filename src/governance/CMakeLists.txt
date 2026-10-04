set(governance_sources
    vote_proof.cpp
    vote_proof_verifier.cpp
    vote_utils.cpp
    vote_manager.cpp
    voting_weight.cpp
    vote_serialization.cpp
    proposal.cpp
    proposal_serialization.cpp
    lifecycle_manager.cpp
    execution.cpp
    treasury.cpp
    governance.cpp
    governance_db.cpp
    governance_engine.cpp
    governance_params.cpp
    dao_clsag.cpp
    dao_weight.cpp
    dao_vote_or_proof.cpp
    dao_paillier.cpp
    dao_threshold.cpp
    dao_tally.cpp
    dao_tally_share.cpp
    tally_manager.cpp
    dao_dkg.cpp
    dao_wallet_v2.cpp
    dao_dkg_transport.cpp
    dao_consistency.cpp
    parameter_manager.cpp
)

monero_add_library(obj_governance OBJECT ${governance_sources})
target_link_libraries(obj_obj_governance PRIVATE secp256k1)

target_include_directories(obj_governance PRIVATE ${CMAKE_SOURCE_DIR}/src)

# Test-only DKG accessors. Enabled only when the parent build defines
# VEILROOT_DAO_DKG_TESTING_BUILD=1, which the unit_tests CMakeLists
# sets before including this file.
if (VEILROOT_DAO_DKG_TESTING_BUILD)
  target_compile_definitions(obj_obj_governance PRIVATE VEILROOT_DAO_DKG_TESTING=1)
endif ()