#
# CMakeLists.txt: abandon all hope, etc etc etc
#
# This file is part of Sweet B, a safe, compact, embeddable elliptic curve
# cryptography library.
#
# Sweet B is provided under the terms of the included LICENSE file. All
# other rights are reserved.
#
# Copyright 2017 Wearable Inc.
#

cmake_minimum_required(VERSION 3.5)

project(sweet_b LANGUAGES C VERSION 0.1.0)
include(GNUInstallDirs)

set(CMAKE_C_STANDARD 11)

if("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang" OR
        "${CMAKE_C_COMPILER_ID}" STREQUAL "AppleClang")
    message(STATUS "Enabling clang options")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Weverything -Wno-padded")
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=undefined")
endif()
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -pedantic -Wextra -Wno-unused-parameter")

set(SB_SOURCES

        sb_sha256.c
        sb_hmac_sha256.c
        sb_hmac_drbg.c

        sb_fe.c
        sb_sw_lib.c)

add_executable(sb_test ${SB_SOURCES} sb_test.c)

# 16x16->32 operations are most likely to accidentally trigger UB if there is
# a missing cast from implicitly promoted int to uint32_t

# If you update the SB_HMAC_DRBG options here to make unit tests pass, you
# must also update the checks in sb_hmac_drbg.h

target_compile_definitions(sb_test PRIVATE SB_TEST SB_MUL_SIZE=2
        SB_DEBUG_ASSERTS
        SB_HMAC_DRBG_RESEED_INTERVAL=8
        SB_HMAC_DRBG_MAX_BYTES_PER_REQUEST=128
        SB_HMAC_DRBG_MAX_ENTROPY_INPUT_LENGTH=128)

add_library(sweet_b SHARED ${SB_SOURCES})

set_target_properties(sweet_b PROPERTIES
        VERSION ${PROJECT_VERSION}
        PUBLIC_HEADER sb_sw_lib.h sb_fe.h sb_hmac_drbg.h sb_hmac_sha256.h
        sb_sha256.h sb_sw_context.h sb_types.h)

install(TARGETS sweet_b
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
