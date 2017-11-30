/*
 * sb_hmac_drbg.c: implementation of HMAC-DRBG using SHA-256
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

#include "sb_hmac_drbg.h"

#include <string.h>

#ifdef SB_TEST

#include <assert.h>

#endif

// entropy_input || nonce || personalization
#define UPDATE_VECTORS SB_HMAC_DRBG_ADD_VECTOR_LEN

// For use in HMAC-DRBG only; assumes the current key is SB_SHA256_SIZE bytes.
extern void sb_hmac_sha256_finish_to_key(sb_hmac_sha256_state_t hmac[static 1]);

// K = HMAC(K, V || r || provided_data)
// V = HMAC(K, V)
static void sb_hmac_drbg_update_step
    (sb_hmac_drbg_state_t drbg[static const 1],
     const sb_byte_t r[static const 1],
     const sb_byte_t* const provided[static const UPDATE_VECTORS],
     const size_t provided_len[static const UPDATE_VECTORS])
{
    sb_hmac_sha256_reinit(&drbg->hmac);
    sb_hmac_sha256_update(&drbg->hmac, drbg->V, SB_SHA256_SIZE);
    sb_hmac_sha256_update(&drbg->hmac, r, 1);
    for (size_t i = 0; i < UPDATE_VECTORS; i++) {
        if (provided_len[i] > 0) {
            sb_hmac_sha256_update(&drbg->hmac, provided[i],
                                  provided_len[i]);
        }
    }
    sb_hmac_sha256_finish_to_key(&drbg->hmac);
    sb_hmac_sha256_update(&drbg->hmac, drbg->V, SB_SHA256_SIZE);
    sb_hmac_sha256_finish(&drbg->hmac, drbg->V);
}

static void sb_hmac_drbg_update_vec
    (sb_hmac_drbg_state_t drbg[static const 1],
     const sb_byte_t* const provided[static const UPDATE_VECTORS],
     const size_t provided_len[static const UPDATE_VECTORS],
     _Bool any_provided)
{
    static const sb_byte_t r0 = 0x00, r1 = 0x01;
    sb_hmac_drbg_update_step(drbg, &r0, provided, provided_len);
    if (any_provided) {
        sb_hmac_drbg_update_step(drbg, &r1, provided, provided_len);
    }
}

sb_hmac_drbg_err_t sb_hmac_drbg_reseed
    (sb_hmac_drbg_state_t drbg[static const 1],
     const sb_byte_t* const entropy,
     const size_t entropy_len,
     const sb_byte_t* const additional,
     const size_t additional_len)
{
    if (entropy_len < SB_HMAC_DRBG_MIN_ENTROPY_INPUT_LENGTH) {
        return SB_HMAC_DRBG_ERR_INSUFFICIENT_ENTROPY;
    }

    if (entropy_len > SB_HMAC_DRBG_MAX_ENTROPY_INPUT_LENGTH ||
        additional_len > SB_HMAC_DRBG_MAX_ADDITIONAL_INPUT_LENGTH) {
        return SB_HMAC_DRBG_ERR_INPUT_TOO_LARGE;
    }

    const sb_byte_t* const a_vec[UPDATE_VECTORS] = {
        entropy, additional, NULL
    };
    const size_t alen_vec[UPDATE_VECTORS] = { entropy_len, additional_len, 0 };
    sb_hmac_drbg_update_vec(drbg, a_vec, alen_vec, 1);
    drbg->reseed_counter = 1;
    return SB_HMAC_DRBG_SUCCESS;
}

_Bool sb_hmac_drbg_reseed_required(sb_hmac_drbg_state_t const
                                   drbg[static const 1])
{
    return drbg->reseed_counter > SB_HMAC_DRBG_RESEED_INTERVAL;
}

sb_hmac_drbg_err_t sb_hmac_drbg_init(sb_hmac_drbg_state_t drbg[static const 1],
                                     const sb_byte_t* const entropy,
                                     size_t const entropy_len,
                                     const sb_byte_t* const nonce,
                                     size_t const nonce_len,
                                     const sb_byte_t* const personalization,
                                     size_t const personalization_len)
{
    memset(drbg, 0, sizeof(sb_hmac_drbg_state_t));

    // V is all zeros, which is the initial HMAC key
    sb_hmac_sha256_init(&drbg->hmac, drbg->V, SB_SHA256_SIZE);

    memset(drbg->V, 0x01, SB_SHA256_SIZE);

    if (entropy_len < SB_HMAC_DRBG_MIN_ENTROPY_INPUT_LENGTH ||
        nonce_len < SB_HMAC_DRBG_MIN_NONCE_LENGTH) {
        // we require more vespene gas
        return SB_HMAC_DRBG_ERR_INSUFFICIENT_ENTROPY;
    }

    if (entropy_len > SB_HMAC_DRBG_MAX_ENTROPY_INPUT_LENGTH ||
        nonce_len > SB_HMAC_DRBG_MAX_ENTROPY_INPUT_LENGTH ||
        personalization_len > SB_HMAC_DRBG_MAX_PERSONALIZATION_STRING_LENGTH) {
        return SB_HMAC_DRBG_ERR_INPUT_TOO_LARGE;
    }

    const sb_byte_t* const a_vec[UPDATE_VECTORS] = {
        entropy, nonce, personalization
    };

    const size_t alen_vec[UPDATE_VECTORS] = {
        entropy_len, nonce_len, personalization_len
    };

    sb_hmac_drbg_update_vec(drbg, a_vec, alen_vec, 1);

    drbg->reseed_counter = 1;

    return SB_HMAC_DRBG_SUCCESS;
}

sb_hmac_drbg_err_t sb_hmac_drbg_generate_additional_vec
    (sb_hmac_drbg_state_t drbg[static const 1],
     sb_byte_t* restrict output, size_t output_len,
     const sb_byte_t* const additional[static const SB_HMAC_DRBG_ADD_VECTOR_LEN],
     const size_t additional_len[static const SB_HMAC_DRBG_ADD_VECTOR_LEN])
{
    if (output_len > SB_HMAC_DRBG_MAX_BYTES_PER_REQUEST) {
        return SB_HMAC_DRBG_ERR_REQUEST_TOO_LARGE;
    }

    size_t total_additional_len = 0;
    for (size_t i = 0; i < SB_HMAC_DRBG_ADD_VECTOR_LEN; i++) {
        total_additional_len += additional_len[i];
    }

    if (total_additional_len > SB_HMAC_DRBG_MAX_ADDITIONAL_INPUT_LENGTH) {
        return SB_HMAC_DRBG_ERR_INPUT_TOO_LARGE;
    }

    if (drbg->reseed_counter > SB_HMAC_DRBG_RESEED_INTERVAL) {
        return SB_HMAC_DRBG_ERR_RESEED_REQUIRED;
    }

    if (total_additional_len > 0) {
        sb_hmac_drbg_update_vec(drbg, additional, additional_len,
                                total_additional_len > 0);
    }

    while (output_len) {
        size_t gen = output_len > SB_SHA256_SIZE ? SB_SHA256_SIZE : output_len;

        sb_hmac_sha256_reinit(&drbg->hmac);
        sb_hmac_sha256_update(&drbg->hmac, drbg->V, SB_SHA256_SIZE);
        sb_hmac_sha256_finish(&drbg->hmac, drbg->V);

        memcpy(output, drbg->V, gen);
        output += gen;
        output_len -= gen;
    }

    sb_hmac_drbg_update_vec(drbg, additional, additional_len,
                            total_additional_len > 0);
    drbg->reseed_counter++;
    return SB_HMAC_DRBG_SUCCESS;
}

sb_hmac_drbg_err_t sb_hmac_drbg_generate
    (sb_hmac_drbg_state_t drbg[static const 1],
     sb_byte_t* const output,
     size_t const output_len)
{
    const sb_byte_t* additional[SB_HMAC_DRBG_ADD_VECTOR_LEN] = { NULL };
    const size_t additional_len[SB_HMAC_DRBG_ADD_VECTOR_LEN] = { 0 };
    return sb_hmac_drbg_generate_additional_vec(drbg, output, output_len,
                                                additional, additional_len);
}

#ifdef SB_TEST

// TODO: Bring the entire NIST suite into tests, probably in a separate file.

// Every test is initialized with entropy and a nonce. Not every test
// includes personalization data or additional data on generate calls. Thus,
// TEST_Pn, TEST_An, and TEST_AAn are one byte larger than they ordinarily
// would be, so that empty data is represented with a one-byte array.

static const sb_byte_t TEST_E1[] = {
    0xca, 0x85, 0x19, 0x11, 0x34, 0x93, 0x84, 0xbf, 0xfe, 0x89, 0xde, 0x1c,
    0xbd, 0xc4, 0x6e, 0x68, 0x31, 0xe4, 0x4d, 0x34, 0xa4, 0xfb, 0x93, 0x5e,
    0xe2, 0x85, 0xdd, 0x14, 0xb7, 0x1a, 0x74, 0x88
};
static const sb_byte_t TEST_N1[] = {
    0x65, 0x9b, 0xa9, 0x6c, 0x60, 0x1d, 0xc6, 0x9f, 0xc9, 0x02, 0x94, 0x08,
    0x05, 0xec, 0x0c, 0xa8
};

static const sb_byte_t TEST_P1[] = { 0 };
static const sb_byte_t TEST_A1[] = { 0 };
static const sb_byte_t TEST_AA1[] = { 0 };

static const sb_byte_t TEST_R1[] = {
    0xe5, 0x28, 0xe9, 0xab, 0xf2, 0xde, 0xce, 0x54, 0xd4, 0x7c, 0x7e, 0x75,
    0xe5, 0xfe, 0x30, 0x21, 0x49, 0xf8, 0x17, 0xea, 0x9f, 0xb4, 0xbe, 0xe6,
    0xf4, 0x19, 0x96, 0x97, 0xd0, 0x4d, 0x5b, 0x89, 0xd5, 0x4f, 0xbb, 0x97,
    0x8a, 0x15, 0xb5, 0xc4, 0x43, 0xc9, 0xec, 0x21, 0x03, 0x6d, 0x24, 0x60,
    0xb6, 0xf7, 0x3e, 0xba, 0xd0, 0xdc, 0x2a, 0xba, 0x6e, 0x62, 0x4a, 0xbf,
    0x07, 0x74, 0x5b, 0xc1, 0x07, 0x69, 0x4b, 0xb7, 0x54, 0x7b, 0xb0, 0x99,
    0x5f, 0x70, 0xde, 0x25, 0xd6, 0xb2, 0x9e, 0x2d, 0x30, 0x11, 0xbb, 0x19,
    0xd2, 0x76, 0x76, 0xc0, 0x71, 0x62, 0xc8, 0xb5, 0xcc, 0xde, 0x06, 0x68,
    0x96, 0x1d, 0xf8, 0x68, 0x03, 0x48, 0x2c, 0xb3, 0x7e, 0xd6, 0xd5, 0xc0,
    0xbb, 0x8d, 0x50, 0xcf, 0x1f, 0x50, 0xd4, 0x76, 0xaa, 0x04, 0x58, 0xbd,
    0xab, 0xa8, 0x06, 0xf4, 0x8b, 0xe9, 0xdc, 0xb8,
};

void sb_test_hmac_drbg(void)
{
    sb_byte_t r[128];
    sb_hmac_drbg_state_t drbg;
    const sb_byte_t* add[SB_HMAC_DRBG_ADD_VECTOR_LEN] = { NULL };
    size_t add_len[SB_HMAC_DRBG_ADD_VECTOR_LEN] = { 0 };
    assert(sb_hmac_drbg_init(&drbg, TEST_E1, sizeof(TEST_E1), TEST_N1, sizeof
    (TEST_N1), TEST_P1 + 1, sizeof(TEST_P1) - 1) == SB_HMAC_DRBG_SUCCESS);
    add[0] = TEST_A1 + 1;
    add_len[0] = sizeof(TEST_A1) - 1;
    assert(
        sb_hmac_drbg_generate_additional_vec(&drbg, r, sizeof(TEST_R1),
                                             add, add_len) ==
        SB_HMAC_DRBG_SUCCESS);
    add[0] = TEST_AA1 + 1;
    add_len[0] = sizeof(TEST_AA1) - 1;
    assert(
        sb_hmac_drbg_generate_additional_vec(&drbg, r, sizeof(TEST_R1),
                                             add, add_len) ==
        SB_HMAC_DRBG_SUCCESS);
    assert(memcmp(r, TEST_R1, sizeof(TEST_R1)) == 0);
}

#endif
