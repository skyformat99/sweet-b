/*
 * sb_sw_lib.h: public API for operations on elliptic curves
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

#ifndef SB_SW_LIB_H
#define SB_SW_LIB_H

// sb_sw_lib.h: the main entry point for short-Weierstrass curves

#include <stdint.h>

#include "sb_types.h"
#include "sb_hmac_drbg.h"
#include "sb_sw_context.h"

// see sb_types.h for the definition of sb_single_t and sb_double_t
typedef sb_single_t sb_sw_private_t;
typedef sb_single_t sb_sw_shared_secret_t;
typedef sb_single_t sb_sw_compressed_public_t;
typedef sb_single_t sb_sw_message_digest_t;
typedef sb_double_t sb_sw_public_t;
typedef sb_double_t sb_sw_signature_t;

typedef enum sb_sw_curve_id_t {
    SB_SW_CURVE_P256 = 0,
    SB_SW_CURVE_SECP256K1 = 1
} sb_sw_curve_id_t;

// see sb_types.h for the definition of sb_data_endian_t

// All of the following methods take an initial parameter of type
// sb_sw_context_t. You are responsible for allocating this context
// structure. You may allocate different structures for each call or reuse
// the same structure multiple times. The context is small (512 bytes) and
// may be stack allocated.

// sb_sw_generate_private_key:

// Using the given HMAC-DRBG instance, generate a private key and return it
// in private. Fails if the curve specified is invalid, if the DRBG must be
// reseeded, or in the infinitesimal chance that two generated private keys
// are invalid (probability no greater than 2^-64). You are responsible for
// ensuring that the HMAC-DRBG instance supplied has been seeded with
// sufficient entropy at initialization time.

// This is the only method which requires a HMAC-DRBG instance to be passed.
// You do not need to use this method to generate private keys. Alternatively,
// you could repeatedly call sb_sw_compute_public_key with random bytes until
// it succeeds.

// If you are unfamiliar with the [static 1] syntax, this declaration tells
// the compiler that the passed pointer is non-NULL.

extern _Bool sb_sw_generate_private_key(sb_sw_context_t context[static 1],
                                        sb_sw_private_t private[static 1],
                                        sb_hmac_drbg_state_t drbg[static 1],
                                        sb_sw_curve_id_t curve,
                                        sb_data_endian_t e);

// sb_sw_compute_private_key:

// Returns the public key for the supplied private key. The drbg parameter is
// optional and is used for Z blinding. Fails if the curve specified is
// invalid, the private key supplied is invalid, or if the optionally
// supplied drbg requires reseeding.

extern _Bool sb_sw_compute_public_key(sb_sw_context_t context[static 1],
                                      sb_sw_public_t public[static 1],
                                      const sb_sw_private_t private[static 1],
                                      sb_hmac_drbg_state_t* drbg,
                                      sb_sw_curve_id_t curve,
                                      sb_data_endian_t e);

// sb_sw_valid_public_key:

// Returns true if the supplied public key is valid. Fails if the curve
// supplied is invalid.

extern _Bool sb_sw_valid_public_key(sb_sw_context_t context[static 1],
                                    const sb_sw_public_t public[static 1],
                                    sb_sw_curve_id_t curve,
                                    sb_data_endian_t e);

// sb_sw_shared_secret:

// Generate an ECDH shared secret using the given private key and public key.
// You SHOULD use this shared secret as input to a key-derivation function
// (KDF) instead of using it directly. Selection of an appropriate KDF is
// application-specific and outside the scope of Sweet B; however, most
// hash-based KDFs are easily implemented using the supplied SHA256 and
// HMAC-SHA256 procedures. See RFC5869 for one such KDF scheme, and NIST
// SP800-56A rev. 2 for details on a single-step SHA256-based scheme.

// Fails if the supplied curve, private, or public keys are invalid, or if
// the optionally supplied drbg requires reseeding.

extern _Bool sb_sw_shared_secret(sb_sw_context_t context[static 1],
                                 sb_sw_shared_secret_t secret[static 1],
                                 const sb_sw_private_t private[static 1],
                                 const sb_sw_public_t public[static 1],
                                 sb_hmac_drbg_state_t* drbg,
                                 sb_sw_curve_id_t curve,
                                 sb_data_endian_t e);

// sb_sw_sign_message_digest

// Signs the 32-byte message digest using the provided private key. If a drbg
// is supplied, it will be used for the per-message secret generation. The
// private key and message are used as additional input to the drbg to ensure
// that the per-message secret is always unique per (private key, message)
// combination. If no drbg is supplied, RFC6979 deterministic secret
// generation is used instead. Fails if the supplied curve or private key are
// invalid, or if the optionally supplied drbg requires reseeding.

extern _Bool sb_sw_sign_message_digest(sb_sw_context_t context[static 1],
                                       sb_sw_signature_t signature[static 1],
                                       const sb_sw_private_t private[static 1],
                                       const sb_sw_message_digest_t
                                       message[static 1],
                                       sb_hmac_drbg_state_t* drbg,
                                       sb_sw_curve_id_t curve,
                                       sb_data_endian_t e);

// sb_sw_verify_signature

// Verifies the supplied message digest signature. Fails if the supplied
// curve or public key is invalid, if the message signature is invalid, or
// if the optionally supplied drbg requires reseeding.

extern _Bool sb_sw_verify_signature(sb_sw_context_t context[static 1],
                                    const sb_sw_signature_t signature[static 1],
                                    const sb_sw_public_t public[static 1],
                                    const sb_sw_message_digest_t
                                    message[static 1],
                                    sb_hmac_drbg_state_t* drbg,
                                    sb_sw_curve_id_t curve,
                                    sb_data_endian_t e);

#ifdef SB_TEST

// Unit tests:

extern void sb_test_sw_point_mult_add(void);
extern void sb_test_exceptions(void);
extern void sb_test_mont_point_mult(void);
extern void sb_test_shared_secret(void);
extern void sb_test_compute_public(void);
extern void sb_test_valid_public(void);
extern void sb_test_sign_rfc6979(void);
extern void sb_test_sign_catastrophe(void);
extern void sb_test_verify(void);
extern void sb_test_verify_invalid(void);
extern void sb_test_shared_secret_k256(void);
extern void sb_test_sign_k256(void);
extern void sb_test_sign_iter(void);
extern void sb_test_sign_iter_k256(void);
extern void sb_test_shared_iter(void);
extern void sb_test_shared_iter_k256(void);
#endif

#endif
