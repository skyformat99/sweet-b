/*
 * sb_types.h: public API for common types
 *
 * This file is part of Sweet B, a safe, compact, embeddable elliptic curve
 * cryptography library.
 *
 * Sweet B is provided under the terms of the included LICENSE file. All
 * other rights are reserved.
 *
 * Copyright 2017 Wearable Inc.
 *
 */

#ifndef SB_TYPES_H
#define SB_TYPES_H

#include <stdint.h>

#define SB_ELEM_BYTES 32

typedef uint8_t sb_byte_t;
// Used to indicate "a bunch of bytes" instead of "an 8-bit integer we're
// doing arithmetic on"

typedef struct sb_single_t {
    sb_byte_t bytes[SB_ELEM_BYTES];
} sb_single_t;

typedef struct sb_double_t {
    sb_byte_t bytes[SB_ELEM_BYTES * 2];
} sb_double_t;

typedef enum {
    SB_DATA_ENDIAN_LITTLE = 0,
    SB_DATA_ENDIAN_BIG
} sb_data_endian_t;

#endif
