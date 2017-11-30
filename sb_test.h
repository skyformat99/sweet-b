/*
 * sb_test.h: private API for Sweet B unit tests and debug assertions
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

#ifndef SB_TEST_H
#define SB_TEST_H

#ifdef SB_TEST

#include <stdio.h>
#include <assert.h>
#include <string.h>

#endif

#if defined(SB_DEBUG_ASSERTS) || defined(SB_TEST)
#include <assert.h>
#define SB_ASSERT(e, s) assert((e) && (s)[0])
#else
#define SB_ASSERT(e, s) do { } while (0)
#endif

#endif
