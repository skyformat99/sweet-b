/*
 * sb_hmac_drbg.h: public API for HMAC-DRBG using SHA-256
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

// This implementation of HMAC-DRBG based on SHA256 is provided for use in
// RFC6979-based deterministic signing. It's also appropriate for general use
// as a DRBG, so if you have access to a raw source of entropy such as an
// on-chip RNG, you should consider using this for key generation.

#ifndef SB_HMAC_DRBG_H
#define SB_HMAC_DRBG_H

#include "sb_hmac_sha256.h"

// Per SP 800-57 Part 1 Rev. 4, 5.6.1: HMAC-SHA-256 has security strength >=256
// This constant is in bytes, not bits
#define SB_HMAC_DRBG_SECURITY_STRENGTH 32

// Use these in your application when providing entropy
#define SB_HMAC_DRBG_MIN_ENTROPY_INPUT_LENGTH SB_HMAC_DRBG_SECURITY_STRENGTH
#define SB_HMAC_DRBG_MIN_NONCE_LENGTH (SB_HMAC_DRBG_SECURITY_STRENGTH / 2)

#if defined(SB_HMAC_DRBG_RESEED_INTERVAL)

#if SB_HMAC_DRBG_RESEED_INTERVAL > 0x1000000000000
#error "SB_HMAC_DRBG_RESEED_INTERVAL too large; see SP 800-90A Rev. 1"
#elif SB_HMAC_DRBG_RESEED_INTERVAL < 8
// Sweet B unit tests depend on this
// Note that Sweet B does NOT support prediction resistance! If you want the
// equivalent, reseed the DRBG before every operation yourself.
#error "SB_HMAC_DRBG_RESEED_INTERVAL is nonsense"
#endif

#else
// In practice, this should be much more frequent
#define SB_HMAC_DRBG_RESEED_INTERVAL 1024
#endif

// These are arbitrary limits and may be overridden

#if defined(SB_HMAC_DRBG_MAX_BYTES_PER_REQUEST)

#if SB_HMAC_DRBG_MAX_BYTES_PER_REQUEST > 65536
#error "SB_HMAC_DRBG_MAX_BYTES_PER_REQUEST too large; see SP 800-90A Rev. 1"
#elif SB_HMAC_DRBG_MAX_BYTES_PER_REQUEST < 128
// Sweet B unit tests depend on being able to generate 128 bytes at a time
#error "SB_HMAC_DRBG_MAX_BYTES_PER_REQUEST is nonsense"
#endif

#else
#define SB_HMAC_DRBG_MAX_BYTES_PER_REQUEST 1024
#endif

#if defined(SB_HMAC_DRBG_MAX_ENTROPY_INPUT_LENGTH)

#if SB_HMAC_DRBG_MAX_ENTROPY_INPUT_LENGTH > 0x100000000
#error "SB_HMAC_DRBG_MAX_ENTROPY_INPUT_LENGTH too large; see SP 800-90A Rev. 1"
#elif SB_HMAC_DRBG_MAX_ENTROPY_INPUT_LENGTH < 128
// Sweet B depends on being able to input 128 bytes of additional data
// See below; the limit is the same for entropy and additional data
#error "SB_HMAC_DRBG_MAX_ENTROPY_INPUT_LENGTH is nonsense"
#endif

#else
#define SB_HMAC_DRBG_MAX_ENTROPY_INPUT_LENGTH 1024
#endif

// Is there a good reason to have separate limits here?
#define SB_HMAC_DRBG_MAX_ADDITIONAL_INPUT_LENGTH SB_HMAC_DRBG_MAX_ENTROPY_INPUT_LENGTH
#define SB_HMAC_DRBG_MAX_PERSONALIZATION_STRING_LENGTH SB_HMAC_DRBG_MAX_ENTROPY_INPUT_LENGTH

typedef enum {
    SB_HMAC_DRBG_SUCCESS = 0,
    SB_HMAC_DRBG_ERR_INSUFFICIENT_ENTROPY,
    SB_HMAC_DRBG_ERR_INPUT_TOO_LARGE,
    SB_HMAC_DRBG_ERR_REQUEST_TOO_LARGE,
    SB_HMAC_DRBG_ERR_RESEED_REQUIRED
} sb_hmac_drbg_err_t;

typedef struct sb_hmac_drbg_state_t {
    sb_hmac_sha256_state_t hmac;
    sb_byte_t V[SB_SHA256_SIZE];
    size_t reseed_counter;
} sb_hmac_drbg_state_t;

extern sb_hmac_drbg_err_t sb_hmac_drbg_init(sb_hmac_drbg_state_t drbg[static 1],
                                            const sb_byte_t* entropy,
                                            size_t entropy_len,
                                            const sb_byte_t* nonce,
                                            size_t nonce_len,
                                            const sb_byte_t* personalization,
                                            size_t personalization_len);

extern sb_hmac_drbg_err_t sb_hmac_drbg_reseed(sb_hmac_drbg_state_t drbg[static 1],
                                              const sb_byte_t* entropy,
                                              size_t entropy_len,
                                              const sb_byte_t* additional,
                                              size_t additional_len);

extern _Bool sb_hmac_drbg_reseed_required(sb_hmac_drbg_state_t const
                                          drbg[static 1]);

extern sb_hmac_drbg_err_t sb_hmac_drbg_generate(sb_hmac_drbg_state_t drbg[static 1],
                                                sb_byte_t* output,
                                                size_t output_len);

// Generate with a vector of additional data, which can be supplied in up to
// SB_HMAC_DRBG_ADD_VECTOR_LEN pointers. If any additional data is supplied,
// the first entry in the vector must be non-NULL.

#define SB_HMAC_DRBG_ADD_VECTOR_LEN 3

// output must NOT alias any part of the additional data
extern sb_hmac_drbg_err_t sb_hmac_drbg_generate_additional_vec
    (sb_hmac_drbg_state_t drbg[static 1],
     sb_byte_t* restrict output, size_t output_len,
     const sb_byte_t* const additional[static SB_HMAC_DRBG_ADD_VECTOR_LEN],
     const size_t additional_len[static SB_HMAC_DRBG_ADD_VECTOR_LEN]);

#ifdef SB_TEST
extern void sb_test_hmac_drbg(void);
#endif

#endif
