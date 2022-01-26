# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.13)

project(SEALExamples VERSION 3.7.2 LANGUAGES CXX)

# If not called from root CMakeLists.txt
if(NOT DEFINED SEAL_BUILD_EXAMPLES)
    set(SEAL_BUILD_EXAMPLES ON)

    # Import Microsoft SEAL
    find_package(SEAL 3.7.2 EXACT REQUIRED)

    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin)
endif()

if(SEAL_BUILD_EXAMPLES)
    add_executable(sealexamples)
    target_include_directories(sealexamples PUBLIC /scale/cal/home-interns/gina7484/intel/oneapi/vtune/latest/sdk/include
     /scale/cal/home-interns/gina7484/SEAL/native/src)

    target_link_directories(sealexamples PUBLIC /scale/cal/home-interns/gina7484/intel/oneapi/vtune/latest/sdk/lib32
     /scale/cal/home-interns/gina7484/intel/oneapi/vtune/latest/sdk/lib64)

    target_link_libraries(sealexamples PUBLIC /scale/cal/home-interns/gina7484/intel/oneapi/vtune/latest/sdk/lib64/libittnotify.a)
    target_link_libraries(sealexamples PUBLIC ${CMAKE_DL_LIBS})

    if(NOT DEFINED SEAL_BUILD_ORG_EXAMPLES)
        set(SEAL_BUILD_ORG_EXAMPLES OFF)
    endif()

    if(SEAL_BUILD_ORG_EXAMPLES)
        target_sources(sealexamples
            PRIVATE
                ${CMAKE_CURRENT_LIST_DIR}/examples.cpp
                ${CMAKE_CURRENT_LIST_DIR}/1_bfv_basics.cpp
                ${CMAKE_CURRENT_LIST_DIR}/2_encoders.cpp
                ${CMAKE_CURRENT_LIST_DIR}/3_levels.cpp
                ${CMAKE_CURRENT_LIST_DIR}/4_ckks_basics.cpp
                ${CMAKE_CURRENT_LIST_DIR}/5_rotation.cpp
                ${CMAKE_CURRENT_LIST_DIR}/6_serialization.cpp
                ${CMAKE_CURRENT_LIST_DIR}/7_performance.cpp
        )
    else()
        target_sources(sealexamples
            PRIVATE
                ${CMAKE_CURRENT_LIST_DIR}/profile/profile_mult.cpp
        )
    endif()

    if(TARGET SEAL::seal)
        target_link_libraries(sealexamples PRIVATE SEAL::seal)
    elseif(TARGET SEAL::seal_shared)
        target_link_libraries(sealexamples PRIVATE SEAL::seal_shared)
    else()
        message(FATAL_ERROR "Cannot find target SEAL::seal or SEAL::seal_shared")
    endif()
endif()
