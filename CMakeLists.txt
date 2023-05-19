cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake"
     "${CMAKE_CURRENT_LIST_DIR}/cmake/modules/share/modules/cmake")

include(CMConfig)
include(CMDeploy)
include(CMSetupVersion)
include(CompileCircuit)

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

cm_project(sync_committee WORKSPACE_NAME ${CMAKE_WORKSPACE_NAME} LANGUAGES ASM C CXX)

cm_setup_version(VERSION 0.1.0 PREFIX ${CMAKE_WORKSPACE_NAME}_${CMAKE_PROJECT_NAME})

add_library(${CMAKE_WORKSPACE_NAME}_${CMAKE_PROJECT_NAME} OBJECT
            include/ethereum/sync_committee/constants.hpp
            include/ethereum/sync_committee/hash_to_field.hpp
            src/inputs.cpp
            src/poseidon.cpp
            src/ssz.cpp
            src/sync_committee.cpp)

set_target_properties(${CMAKE_WORKSPACE_NAME}_${CMAKE_PROJECT_NAME} PROPERTIES
                      LINKER_LANGUAGE CXX
                      EXPORT_NAME ${CMAKE_PROJECT_NAME}
                      CXX_STANDARD 17
                      CXX_STANDARD_REQUIRED TRUE)

add_circuit(${CMAKE_WORKSPACE_NAME}_${CMAKE_PROJECT_NAME}_step
            SOURCES src/step.cpp

            INCLUDE_DIRECTORIES
            $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>

            LINK_LIBRARIES
            crypto3::algebra
            crypto3::block
            crypto3::blueprint
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

            ${CMAKE_WORKSPACE_NAME}_${CMAKE_PROJECT_NAME}

            ${Boost_LIBRARIES})

set_target_properties(${CMAKE_WORKSPACE_NAME}_${CMAKE_PROJECT_NAME}_step PROPERTIES
                      LINKER_LANGUAGE CXX
                      EXPORT_NAME ${CMAKE_PROJECT_NAME}
                      CXX_STANDARD 17
                      CXX_STANDARD_REQUIRED TRUE)

add_circuit(${CMAKE_WORKSPACE_NAME}_${CMAKE_PROJECT_NAME}_rotate
            SOURCES src/rotate.cpp

            INCLUDE_DIRECTORIES
            $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>

            LINK_LIBRARIES
            crypto3::algebra
            crypto3::block
            crypto3::blueprint
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

            ${CMAKE_WORKSPACE_NAME}_${CMAKE_PROJECT_NAME}

            ${Boost_LIBRARIES})

set_target_properties(${CMAKE_WORKSPACE_NAME}_${CMAKE_PROJECT_NAME}_rotate PROPERTIES
                      LINKER_LANGUAGE CXX
                      EXPORT_NAME ${CMAKE_PROJECT_NAME}
                      CXX_STANDARD 17
                      CXX_STANDARD_REQUIRED TRUE)