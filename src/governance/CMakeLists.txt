set(governance_sources
    vote_proof.cpp
    vote_proof_verifier.cpp
    vote_utils.cpp
    vote_manager.cpp
    proposal.cpp
    lifecycle_manager.cpp
    execution.cpp
    treasury.cpp
    governance.cpp
    governance_db.cpp
    governance_engine.cpp
    governance_params.cpp
    parameter_manager.cpp
)

monero_add_library(obj_governance OBJECT ${governance_sources})
target_link_libraries(obj_governance PUBLIC)

target_include_directories(obj_governance PRIVATE ${CMAKE_SOURCE_DIR}/src)