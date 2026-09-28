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
    parameter_manager.cpp
)

monero_add_library(obj_governance OBJECT ${governance_sources})
target_link_libraries(obj_obj_governance PRIVATE secp256k1)

target_include_directories(obj_governance PRIVATE ${CMAKE_SOURCE_DIR}/src)