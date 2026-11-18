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
    dao_crypto_backend.cpp
    dao_tally.cpp
    dao_tally_share.cpp
    tally_manager.cpp
    dao_dkg.cpp
    dao_wallet_v2.cpp
    dao_dkg_transport.cpp
    dao_consistency_context.cpp
    parameter_manager.cpp
)

    list(APPEND governance_sources dao_crypto_backend_cl.cpp)
    list(APPEND governance_sources dao_cl_consistency.cpp)
    list(APPEND governance_sources dao_cl_threshold.cpp)
    list(APPEND governance_sources dao_cl_party.cpp)
    list(APPEND governance_sources dao_cl_dkg_payload.cpp)
    list(APPEND governance_sources dao_cl_dkg_runner.cpp)
    list(APPEND governance_sources dao_cl_reshare.cpp)
    list(APPEND governance_sources dao_cl_reshare_runner.cpp)
    list(APPEND governance_sources dao_cl_tally_wire.cpp)
    list(APPEND governance_sources dao_cl_ballot.cpp)

monero_add_library(obj_governance OBJECT ${governance_sources})
    target_compile_definitions(obj_obj_governance PRIVATE VEILROOT_ENABLE_CL=1)
    target_link_libraries(obj_obj_governance PRIVATE bicycl gmp::gmp)
target_link_libraries(obj_obj_governance PRIVATE secp256k1)

target_include_directories(obj_governance PRIVATE ${CMAKE_SOURCE_DIR}/src)

# Test-only DKG accessors. Enabled only when the parent build defines
# VEILROOT_DAO_DKG_TESTING_BUILD=1, which the unit_tests CMakeLists
# sets before including this file.
if (VEILROOT_DAO_DKG_TESTING_BUILD)
  target_compile_definitions(obj_obj_governance PRIVATE VEILROOT_DAO_DKG_TESTING=1)
endif ()

