/*
 * sb_sw_context.h: private context structure for short Weierstrass curves
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

#ifndef SB_SW_CONTEXT_H
#define SB_SW_CONTEXT_H

#include "sb_fe.h"
#include "sb_hmac_drbg.h"

typedef struct sb_sw_context_t {
    // State variables consumed or produced by HMAC-DRBG during RFC6979
    // deterministic signing
    sb_fe_t h[4];

    union {
        struct {
            sb_hmac_drbg_state_t drbg_state;
            sb_byte_t buf[2 * SB_ELEM_BYTES];
        };
        sb_fe_t c[12];
    };
} sb_sw_context_t;

#endif
