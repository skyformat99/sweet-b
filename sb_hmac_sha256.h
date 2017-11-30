/*
 * sb_hmac_sha256.h: public API for HMAC-SHA-256
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

#ifndef SB_HMAC_SHA256_H
#define SB_HMAC_SHA256_H

#include "sb_sha256.h"

typedef struct sb_hmac_sha256_state_t {
    sb_sha256_state_t sha;
    sb_byte_t key[SB_SHA256_BLOCK_SIZE];
} sb_hmac_sha256_state_t;

extern void sb_hmac_sha256_init(sb_hmac_sha256_state_t hmac[static 1],
                                const sb_byte_t* key,
                                size_t keylen);

extern void sb_hmac_sha256_reinit(sb_hmac_sha256_state_t hmac[static 1]);

extern void sb_hmac_sha256_update(sb_hmac_sha256_state_t hmac[static 1],
                                  const sb_byte_t* input,
                                  size_t len);

extern void sb_hmac_sha256_finish(sb_hmac_sha256_state_t hmac[static 1],
                                  sb_byte_t output[static SB_SHA256_SIZE]);

extern void sb_hmac_sha256(sb_hmac_sha256_state_t hmac[static 1],
                           const sb_byte_t* key,
                           size_t keylen, const sb_byte_t* input,
                           size_t len, sb_byte_t output[static SB_SHA256_SIZE]);


#ifdef SB_TEST
extern void sb_test_hmac_sha256(void);
#endif

#endif
