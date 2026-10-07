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
    dao_tally_key.cpp
    dao_tally_session_cycle.cpp
    parameter_manager.cpp
)

# The Reset module is a cryptographic primitive, not part of the
# production DAO lifecycle. It builds as a separate object library so
# that its unit tests can link it while the daemon and wallet cannot.
set(governance_experimental_sources
    dao_dkg_reset.cpp
    dao_dkg_reset_transcript.cpp
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

monero_add_library(obj_governance_experimental OBJECT ${governance_experimental_sources})
target_include_directories(obj_governance_experimental PRIVATE ${CMAKE_SOURCE_DIR}/src)
if (VEILROOT_DAO_DKG_TESTING_BUILD)
  target_compile_definitions(obj_obj_governance_experimental PRIVATE VEILROOT_DAO_DKG_TESTING=1)
endif ()
