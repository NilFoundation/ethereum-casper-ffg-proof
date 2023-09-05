cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake"
     "${CMAKE_CURRENT_LIST_DIR}/cmake/modules/share/modules/cmake")

include(CMConfig)
include(CMDeploy)
include(CMSetupVersion)

cm_workspace(ethereum)

macro(cm_find_package NAME)
    if(NOT "${NAME}" MATCHES "^${CMAKE_WORKSPACE_NAME}_.*$" AND NOT "${NAME}" STREQUAL CM)
        find_package(${ARGV})
    else()
        set(${ARGV0}_FOUND ON CACHE BOOL "")
    endif()
endmacro()

cm_setup_version(VERSION 0.1.0 PREFIX ${CMAKE_WORKSPACE_NAME})

add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/libs/crypto3")

cm_find_package(CM)

cm_project(casper_ffg WORKSPACE_NAME ${CMAKE_WORKSPACE_NAME} LANGUAGES ASM C CXX)

cm_setup_version(VERSION 0.1.0 PREFIX ${CMAKE_WORKSPACE_NAME}_${CMAKE_PROJECT_NAME})

add_library(${CMAKE_WORKSPACE_NAME}_${CMAKE_PROJECT_NAME} INTERFACE
        include/ethereum/consensus_proof/hash_to_field.hpp
        include/ethereum/consensus_proof/constants.hpp
        include/ethereum/consensus_proof/inputs.hpp
        include/ethereum/consensus_proof/ssz.hpp
        include/ethereum/consensus_proof/consensus_proof.hpp
        include/ethereum/consensus_proof/bls.hpp
        include/ethereum/consensus_proof/poseidon.hpp)

target_include_directories(${CMAKE_WORKSPACE_NAME}_${CMAKE_PROJECT_NAME} INTERFACE
                           $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
                           $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>)

target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CMAKE_PROJECT_NAME} INTERFACE
                      crypto3::algebra
                      crypto3::block
                      crypto3::codec
                      crypto3::containers
                      crypto3::hash
                      crypto3::kdf
                      crypto3::mac
                      marshalling::core
                      marshalling::crypto3_algebra
                      marshalling::crypto3_multiprecision
                      marshalling::crypto3_zk
                      crypto3::math
                      crypto3::modes
                      crypto3::multiprecision
                      crypto3::passhash
                      crypto3::pbkdf
                      crypto3::threshold
                      crypto3::pkpad
                      crypto3::pubkey
                      crypto3::random
                      crypto3::stream
                      crypto3::vdf
                      crypto3::zk

                      ${Boost_LIBRARIES})

set_target_properties(${CMAKE_WORKSPACE_NAME}_${CMAKE_PROJECT_NAME} PROPERTIES
                      LINKER_LANGUAGE CXX
                      EXPORT_NAME ${CMAKE_PROJECT_NAME}
                      CXX_STANDARD 20
                      CXX_STANDARD_REQUIRED TRUE)

add_executable(${CMAKE_WORKSPACE_NAME}_${CMAKE_PROJECT_NAME}_step
            src/step.cpp)

target_include_directories(${CMAKE_WORKSPACE_NAME}_${CMAKE_PROJECT_NAME}_step PUBLIC
                           $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
                           $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>)

target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CMAKE_PROJECT_NAME}_step PUBLIC

            ${CMAKE_WORKSPACE_NAME}_${CMAKE_PROJECT_NAME})

set_target_properties(${CMAKE_WORKSPACE_NAME}_${CMAKE_PROJECT_NAME}_step PROPERTIES
                      LINKER_LANGUAGE CXX
                      EXPORT_NAME ${CMAKE_PROJECT_NAME}
                      CXX_STANDARD 20
                      CXX_STANDARD_REQUIRED TRUE)

add_executable(${CMAKE_WORKSPACE_NAME}_${CMAKE_PROJECT_NAME}_rotate
            src/rotate.cpp)

target_include_directories(${CMAKE_WORKSPACE_NAME}_${CMAKE_PROJECT_NAME}_rotate PUBLIC
                           $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
                           $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>)

target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CMAKE_PROJECT_NAME}_rotate PUBLIC

                      ${CMAKE_WORKSPACE_NAME}_${CMAKE_PROJECT_NAME})

set_target_properties(${CMAKE_WORKSPACE_NAME}_${CMAKE_PROJECT_NAME}_rotate PROPERTIES
                      LINKER_LANGUAGE CXX
                      EXPORT_NAME ${CMAKE_PROJECT_NAME}
                      CXX_STANDARD 20
                      CXX_STANDARD_REQUIRED TRUE)