/**
 * \file kw.h
 *
 * \brief This file provides an API key wrapping(KW)
 *        and key wrapping with padding(KWP) as defined in NIST SP800-38F
 *        https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38F.pdf
 *
 * Key-wrapping specifies a deterministic authenticated-encryption mode of operation,
 * according to <em>NIST SP 800-38F: Recommendation for Block Cipher Modes of Operation:
 * Methods for Key Wrapping</em>.
 * Its purpose is to protect cryptographic keys.
 *
 * It's equivalent is RFC 3394, for KW and RFC 5649 for KWP
 * https://tools.ietf.org/html/rfc3394
 * https://tools.ietf.org/html/rfc5649
 *
 * Note: RFC 5649 defines the object IDs for KW and KWP, which is not supported.
 *
 *
 */
/*
 *  Copyright (C) 2018, Arm Limited (or its affiliates), All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of Mbed TLS (https://tls.mbed.org)
 */

#ifndef MBEDTLS_NIST_KW_H
#define MBEDTLS_NIST_KW_H

#include "cipher.h"

#define MBEDTLS_KW_MODE_KW    0
#define MBEDTLS_KW_MODE_KWP   1

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(MBEDTLS_NIST_KW_ALT)
// Regular implementation
//

/**
 * \brief    The KW context-type definition. The KW context is passed
 *           to the APIs called.
 *
 * \note     The definition of this type may change in future library versions.
 *           Don't take any assumptions on this context!
 */
typedef struct {
    mbedtls_cipher_context_t cipher_ctx;    /*!< The cipher context used. */
}
mbedtls_nist_kw_context;

#else  /* MBEDTLS_NIST_KW_ALT */
#include "nist_kw_alt.h"
#endif /* MBEDTLS_NIST_KW_ALT */

/**
 * \brief           This function initializes the specified KW context,
 *                  to make references valid, and prepare the context
 *                  for mbedtls_nist_kw_setkey() or mbedtls_nist_kw_free().
 *
 * \param ctx       The KW context to initialize.
 *
 */
void mbedtls_nist_kw_init( mbedtls_nist_kw_context *ctx );

/**
 * \brief           This function initializes the KW context set in the
 *                  \p ctx parameter and sets the encryption key.
 *
 * \param ctx       The KW context.
 * \param cipher    The 128-bit block cipher to use. Currently supports only AES.
 * \param key       The Key Encryption Key(KEK).
 * \param keybits   The KEK size in bits. This must be acceptable by the cipher.
 * \param isWrap    Determines whether the operation within the context is wrapping or unwrapping
 *
 * \return          \c 0 on success.
 * \return          A KW or cipher-specific error code on failure.
 */
int mbedtls_nist_kw_setkey( mbedtls_nist_kw_context *ctx,
                       mbedtls_cipher_id_t cipher,
                       const unsigned char *key,
                       unsigned int keybits,
                       const int isWrap );

/**
 * \brief   This function releases and clears the specified KW context
 *          and underlying cipher sub-context.
 *
 * \param ctx       The KW context to clear.
 */
void mbedtls_nist_kw_free( mbedtls_nist_kw_context *ctx );

/**
 * \brief           This function encrypts a buffer using KW.
 *
 * \param ctx       The KW context to use for encryption.
 * \param mode      The KW mode to use (MBEDTLS_KW_MODE_KW or MBEDTLS_KW_MODE_KWP)
 * \param input     The buffer holding the input data.
 * \param in_len    The length of the input data in Bytes.
 *                  The input uses units of 8 Bytes called semiblocks.
 *                  <ul><li>For KW mode: a multiple of semiblocks.</li>
 *                  <li>For KWP mode: any length</li></ul>
 * \param output    The buffer holding the output data.
 *                  Must be at least 8 bytes larger than \p in_len for KW
 *                  and 8 bytes larger rounded up to a multiple of 8 bytes for KWP(15 bytes at most).
 * \param out_len   The length of the actual length being written.
 *
 * \return          \c 0 on success.
 * \return          A KW or cipher-specific error code on failure.
 */
int mbedtls_nist_kw_wrap( mbedtls_nist_kw_context *ctx, int mode,
                     const unsigned char *input, size_t in_len,
                     unsigned char *output, size_t* out_len );

/**
 * \brief           This function encrypts a buffer using KW.
 *
 * \param ctx       The KW context to use for encryption.
 * \param mode      The KW mode to use (MBEDTLS_KW_MODE_KW or MBEDTLS_KW_MODE_KWP)
 * \param input     The buffer holding the input data.
 * \param in_len    The length of the input data in Bytes.
 *                  The input uses units of 8 Bytes called semiblocks.
 *                  THe input must be a multiple of semiblocks.
 * \param output    The buffer holding the output data.
 *                  Minimal length for it should be 8 bytes shorter than \p in_len
 * \param out_len   The length of the actual length being written.
 *                  for KWP mode, the length could be up to 15 bytes shorter than \p in_len,
 *                  depending on how much padding was added to the data.
 *
 * \return          \c 0 on success.
 * \return          A KW or cipher-specific error code on failure.
 */
int mbedtls_nist_kw_unwrap( mbedtls_nist_kw_context *ctx, int mode,
                       const unsigned char *input, size_t in_len,
                       unsigned char *output, size_t* out_len );


#if defined(MBEDTLS_SELF_TEST) && defined(MBEDTLS_AES_C)
/**
 * \brief          The KW checkup routine.
 *
 * \return         \c 0 on success.
 * \return         \c 1 on failure.
 */
int mbedtls_nist_kw_self_test( int verbose );
#endif /* MBEDTLS_SELF_TEST && MBEDTLS_AES_C */

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_NIST_KW_H */
