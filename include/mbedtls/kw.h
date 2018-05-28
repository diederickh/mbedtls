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
 * It uses units of 8 Bytes called semiblocks. The minimal number of input semiblocks is:
 * <ul><li>For KW mode: 2 semiblocks.</li>
 * <li>For KWP mode: 1 semiblock.</li></ul>
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

#ifndef MBEDTLS_KW_H
#define MBEDTLS_KW_H

#include "cipher.h"

#define MBEDTLS_ERR_KW_BAD_INPUT       -0x0080 /**< Bad input parameters to the function. */
#define MBEDTLS_ERR_KW_HW_ACCEL_FAILED -0x0082 /**< KW hardware accelerator failed. */

#define MBEDTLS_KEY_WRAPPING_MODE_KW    0
#define MBEDTLS_KEY_WRAPPING_MODE_KWP   1

#ifdef __cplusplus
extern "C" {
#endif

/*! The 64-bit default ICV for KW mode. */
#define MBEDTLS_KW_ICV1             {0xA6A6A6A6, 0xA6A6A6A6}
/*! The 32-bit default ICV for KWP mode. */
#define MBEDTLS_KW_ICV2             {0xA65959A6, 0x00000000}

#if !defined(MBEDTLS_KW_ALT)
// Regular implementation
//

/**
 * \brief    The KW context-type definition. The KW context is passed
 *           to the APIs called.
 */
typedef struct {
    int                      mode;          /*!< The KW mode used. */
    mbedtls_cipher_context_t cipher_ctx;    /*!< The cipher context used. */
}
mbedtls_kw_context;

#else  /* MBEDTLS_KW_ALT */
#include "kw_alt.h"
#endif /* MBEDTLS_KW_ALT */

/**
 * \brief           This function initializes the specified KW context,
 *                  to make references valid, and prepare the context
 *                  for mbedtls_kw_setkey() or mbedtls_kw_free().
 *
 * \param ctx       The KW context to initialize.
 * \param mode      The KW mode to use (MBEDTLS_KEY_WRAPPING_MODE_KW or MBEDTLS_KEY_WRAPPING_MODE_KWP)
 *
 * \param ctx       The KW context to initialize.
 */
void mbedtls_kw_init( mbedtls_kw_context *ctx, int mode );

/**
 * \brief           This function initializes the KW context set in the
 *                  \p ctx parameter and sets the encryption key.
 *
 * \param ctx       The KW context.
 * \param cipher    The 128-bit block cipher to use. Currently supports only AES.
 * \param key       The encryption key.
 * \param keybits   The key size in bits. This must be acceptable by the cipher. Must be 128.
 * \param isWrap    Determines whether the next operation is wrapping or unwrapping
 *
 * \return          \c 0 on success.
 * \return          A KW or cipher-specific error code on failure.
 */
int mbedtls_kw_setkey( mbedtls_kw_context *ctx,
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
void mbedtls_kw_free( mbedtls_kw_context *ctx );

/**
 * \brief           This function encrypts a buffer using KW.
 *
 * \param ctx       The KW context to use for encryption.
 * \param input     The buffer holding the input data.
 * \param in_len    The length of the input data in Bytes.
 * \param output    The buffer holding the output data.
 *                  Must be at least \p length Bytes wide.
 * \param out_len   The length of the output data in Bytes.
 *                  Updated to the actual length being written.
 *
 * \return          \c 0 on success.
 * \return          A KW or cipher-specific error code on failure.
 */
int mbedtls_kw_wrap( mbedtls_kw_context *ctx,
                     const unsigned char *input, size_t in_len,
                     unsigned char *output, size_t* out_len );

/**
 * \brief           This function encrypts a buffer using KW.
 *
 * \param ctx       The KW context to use for encryption.
 * \param input     The buffer holding the input data.
 * \param in_len    The length of the input data in Bytes.
 * \param output    The buffer holding the output data.
 * \param out_len   The length of the output data in Bytes.
 *                  Updated to the actual length being written.
 *
 * \return          \c 0 on success.
 * \return          A KW or cipher-specific error code on failure.
 */
int mbedtls_kw_unwrap( mbedtls_kw_context *ctx,
                       const unsigned char *input, size_t in_len,
                       unsigned char *output, size_t* out_len );


#if defined(MBEDTLS_SELF_TEST) && defined(MBEDTLS_AES_C)
/**
 * \brief          The KW checkup routine.
 *
 * \return         \c 0 on success.
 * \return         \c 1 on failure.
 */
int mbedtls_kw_self_test( int verbose );
#endif /* MBEDTLS_SELF_TEST && MBEDTLS_AES_C */

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_KW_H */
