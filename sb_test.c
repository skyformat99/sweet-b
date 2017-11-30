/*
 * sb_test.c: test driver for Sweet B tests
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

#include "sb_test.h"
#include "sb_fe.h"
#include "sb_sha256.h"
#include "sb_hmac_sha256.h"
#include "sb_hmac_drbg.h"
#include "sb_sw_lib.h"

#ifdef SB_TEST

#define TEST(name) do { \
    printf("test_" #name "... "); \
    sb_test_ ## name(); \
    printf("passed!\n"); \
} while (0)

int main(int argc, char** argv)
{
    if (argc < 2) {
        printf("Running tests:\n");
        TEST(sha256);
        TEST(hmac_sha256);
        TEST(hmac_drbg);
        TEST(fe);
        TEST(mont_mult);
        TEST(mod_expt_p);
        TEST(exceptions);
        TEST(sw_point_mult_add);
        TEST(valid_public);
        TEST(compute_public);
        TEST(shared_secret);
        TEST(sign_rfc6979);
        TEST(sign_catastrophe);
        TEST(verify);
        TEST(verify_invalid);
        TEST(sign_k256);
        TEST(shared_secret_k256);

        // Long tests near the end
        TEST(sign_iter);
        TEST(sign_iter_k256);
        TEST(shared_iter);
        TEST(shared_iter_k256);
    } else {
        for (size_t i = 0; i < 8192; i++) {
            sb_test_verify();
        }
    }
    return 0;
}

#endif
