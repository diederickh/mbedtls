/**
 * \file kw.c
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

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_KW_C)

#include "mbedtls/kw.h"
#include "mbedtls/platform_util.h"

#include <stdint.h>
#include <string.h>

#if defined(MBEDTLS_SELF_TEST) && defined(MBEDTLS_AES_C)
#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf printf
#endif /* MBEDTLS_PLATFORM_C */
#endif /* MBEDTLS_SELF_TEST && MBEDTLS_AES_C */

#if !defined(MBEDTLS_KW_ALT)

#define KW_SEMIBLOCK_LENGTH    8

/*
 * Initialize context
 */
void mbedtls_kw_init( mbedtls_kw_context *ctx, int mode )
{
    memset( ctx, 0, sizeof( mbedtls_kw_context ) );
    ctx->mode = mode;
}

int mbedtls_kw_setkey( mbedtls_kw_context *ctx,
                       mbedtls_cipher_id_t cipher,
                       const unsigned char *key,
                       unsigned int keybits,
                       const int isWrap )
{
    int ret;
    const mbedtls_cipher_info_t *cipher_info;

    /*
     * SP800-38F currently defines AES cipher as the only block cipher allowed, but:
     * "For KW and KWP, the underlying block cipher shall be approved, and the block size shall be
     *  128 bits. Currently, the AES block cipher, with key lengths of 128, 192, or 256 bits, is the only
     *  block cipher that fits this profile."
     */
    if( cipher != MBEDTLS_CIPHER_ID_AES )
        return( MBEDTLS_ERR_KW_BAD_INPUT );

    cipher_info = mbedtls_cipher_info_from_values( cipher, keybits, MBEDTLS_MODE_ECB );
    if( cipher_info == NULL )
        return( MBEDTLS_ERR_KW_BAD_INPUT );

    if( cipher_info->block_size != 16 )
        return( MBEDTLS_ERR_KW_BAD_INPUT );

    mbedtls_cipher_free( &ctx->cipher_ctx );

    if( ( ret = mbedtls_cipher_setup( &ctx->cipher_ctx, cipher_info ) ) != 0 )
        return( ret );

    if( ( ret = mbedtls_cipher_setkey( &ctx->cipher_ctx, key, keybits,
                               isWrap ? MBEDTLS_ENCRYPT : MBEDTLS_DECRYPT ) ) != 0 )
    {
        return( ret );
    }

    return( 0 );
}

/*
 * Free context
 */
void mbedtls_kw_free( mbedtls_kw_context *ctx )
{
    mbedtls_cipher_free( &ctx->cipher_ctx );
    mbedtls_platform_zeroize( ctx, sizeof( mbedtls_kw_context ) );
}

/*
 * KW / KWP - AE
 */
int mbedtls_kw_wrap( mbedtls_kw_context *ctx,
                     const unsigned char *input, size_t in_len,
                     unsigned char *output, size_t* out_len )
{
    int ret = 0;
    const size_t semiBlocks = ( in_len / KW_SEMIBLOCK_LENGTH ) + 1;
    const size_t s = 6 * ( semiBlocks -1 );
    size_t olen, i;
    uint64_t t = 0;
    unsigned char outBuff[ KW_SEMIBLOCK_LENGTH * 2 ];
    unsigned char inBuff[ KW_SEMIBLOCK_LENGTH * 2 ];
    unsigned char* R2 = output + KW_SEMIBLOCK_LENGTH;
    unsigned char* A = output ;
    const uint32_t  ICV1[] = MBEDTLS_KW_ICV1;
    const uint32_t  ICV2[] = MBEDTLS_KW_ICV2;

/*
 * generate the String to work on
 */
    if( ctx->mode == MBEDTLS_KEY_WRAPPING_MODE_KW )
    {
        memcpy( output, ICV1, KW_SEMIBLOCK_LENGTH );
        memcpy( output + KW_SEMIBLOCK_LENGTH, input, in_len );
    }
    else
    {
        size_t padlen = ( 8 - ( in_len % 8) );

        memcpy( output, &ICV2, KW_SEMIBLOCK_LENGTH / 2 );
        memcpy( output + ( KW_SEMIBLOCK_LENGTH / 2 ), &in_len, sizeof(in_len) );
        memcpy( output + ( KW_SEMIBLOCK_LENGTH / 2 ) + sizeof(in_len), input, in_len );
        memset( output + ( KW_SEMIBLOCK_LENGTH / 2 ) + sizeof(in_len) + in_len, 0, padlen );
    }

    if( ( ctx->mode == MBEDTLS_KEY_WRAPPING_MODE_KWP )
            && ( in_len <= KW_SEMIBLOCK_LENGTH ) )
    {
        memcpy( inBuff, output, 16 );
        ret = mbedtls_cipher_update( &ctx->cipher_ctx, inBuff, 16, output, &olen);
        if( ret != 0 )
            goto cleanup;

        *out_len = olen;
    }
    else
    /*
     * Do the wrapping function W
     */
    {
        if( semiBlocks < 3 )
            return MBEDTLS_ERR_KW_BAD_INPUT;

        /* Calculate intermediate values */
        for( t = 1; t <= s; t++ )
        {
            memcpy( inBuff , A, KW_SEMIBLOCK_LENGTH );
            memcpy( inBuff + KW_SEMIBLOCK_LENGTH, R2, KW_SEMIBLOCK_LENGTH );

            ret = mbedtls_cipher_update( &ctx->cipher_ctx, inBuff, 16, outBuff, &olen);
            if( ret != 0 )
                goto cleanup;

            memcpy( A, outBuff, KW_SEMIBLOCK_LENGTH );
            *(uint64_t*)A ^= t;

            /* shift output semiBlocks  */
            for( i = 1; i < semiBlocks - 1; i++ )
                memcpy( output + ( i * KW_SEMIBLOCK_LENGTH ), output + ( ( i + 1 ) * KW_SEMIBLOCK_LENGTH ), KW_SEMIBLOCK_LENGTH );

            /* Set the last semi block as LSB64 of outBuff*/
            memcpy( output + ( ( semiBlocks - 1 ) * KW_SEMIBLOCK_LENGTH ), outBuff + KW_SEMIBLOCK_LENGTH, KW_SEMIBLOCK_LENGTH );
        }

        *out_len = semiBlocks * KW_SEMIBLOCK_LENGTH;
    }
cleanup:

    if( ret != 0)
        mbedtls_platform_zeroize( output, semiBlocks * KW_SEMIBLOCK_LENGTH );
    mbedtls_cipher_finish( &ctx->cipher_ctx, NULL, out_len );
    return ret;
}

/*
 * W-1 function
 */
static int unwrap( mbedtls_kw_context *ctx,
                 const unsigned char *input, size_t semiBlocks,
                 unsigned char *output, size_t* out_len )
{
    int ret = 0;
    const size_t s = 6 * ( semiBlocks -1 );
    size_t olen, i;
    uint64_t t = 0;
    unsigned char outBuff[ KW_SEMIBLOCK_LENGTH * 2 ];
    unsigned char inBuff[ KW_SEMIBLOCK_LENGTH * 2 ];
    unsigned char* R2 = output + KW_SEMIBLOCK_LENGTH ;
    unsigned char* A = output ;

    if( semiBlocks < 3 )
        return MBEDTLS_ERR_KW_BAD_INPUT;

    memcpy( output, input, semiBlocks * KW_SEMIBLOCK_LENGTH );

    /* Calculate intermediate values */
    for( t = s; t >= 1; t-- )
    {
        *(uint64_t*)A ^= t;
        memcpy( inBuff , A, KW_SEMIBLOCK_LENGTH );
        memcpy( inBuff + KW_SEMIBLOCK_LENGTH, output + ( semiBlocks -1 ) * KW_SEMIBLOCK_LENGTH , KW_SEMIBLOCK_LENGTH );

        ret = mbedtls_cipher_update( &ctx->cipher_ctx, inBuff, 16, outBuff, &olen);
        if( ret != 0 )
            goto cleanup;

        memcpy( A, outBuff, KW_SEMIBLOCK_LENGTH );

        /* shift output semiBlocks  */
        for( i = semiBlocks - 2; i > 0; i-- )
            memcpy( output + ( ( i  + 1 ) * KW_SEMIBLOCK_LENGTH ), output + ( ( i ) * KW_SEMIBLOCK_LENGTH ), KW_SEMIBLOCK_LENGTH );

        /* Set R2 as LSB64 of outBuff*/
        memcpy( R2, outBuff + KW_SEMIBLOCK_LENGTH, KW_SEMIBLOCK_LENGTH );
    }

    *out_len = semiBlocks * KW_SEMIBLOCK_LENGTH;

cleanup:
    if( ret != 0)
        mbedtls_platform_zeroize( output, semiBlocks * KW_SEMIBLOCK_LENGTH );

    return ret;
}

/*
 * KW / KWP - AD
 */
int mbedtls_kw_unwrap( mbedtls_kw_context *ctx,
                       const unsigned char *input, size_t in_len,
                       unsigned char *output, size_t* out_len )
{
    int ret = 0;
    size_t i;
    const uint32_t  ICV1[] = MBEDTLS_KW_ICV1;
    const uint32_t  ICV2[] = MBEDTLS_KW_ICV2;

    if( ctx->mode == MBEDTLS_KEY_WRAPPING_MODE_KW )
    {
        ret = unwrap( ctx, input, in_len / KW_SEMIBLOCK_LENGTH, output, out_len);
        if( ret != 0 )
            return ( ret );

        if ( memcmp( ICV1, output, KW_SEMIBLOCK_LENGTH ) != 0 )
        {
            ret = MBEDTLS_ERR_KW_AUTH_FAILED;
            goto cleanup;
        }

        /*
         * shift output to point to P
         */
        for( i=0; i < *out_len;i++ )
        {
            memcpy( output + (i * KW_SEMIBLOCK_LENGTH), output + ( ( i + 1 ) * KW_SEMIBLOCK_LENGTH), KW_SEMIBLOCK_LENGTH );
        }
        *out_len = *out_len - KW_SEMIBLOCK_LENGTH;
    }
    else // KWP
    {
        int padlen = 0;
        size_t Plen;
        if( in_len == KW_SEMIBLOCK_LENGTH * 2 )
        {
            ret = mbedtls_cipher_update( &ctx->cipher_ctx, input, 16, output, out_len);
            if( ret != 0 )
                goto cleanup;
        }
        else if( in_len >  KW_SEMIBLOCK_LENGTH * 2 )
        {
            ret = unwrap( ctx, input, in_len / KW_SEMIBLOCK_LENGTH, output, out_len);
            if( ret != 0 )
                return ( ret );
        }
        if( memcmp( ICV2, output, KW_SEMIBLOCK_LENGTH / 2 ) != 0 )
        {
            ret = MBEDTLS_ERR_KW_AUTH_FAILED;
            goto cleanup;
        }
        memcpy( &Plen, output + KW_SEMIBLOCK_LENGTH / 2, KW_SEMIBLOCK_LENGTH / 2 );

        padlen = 8 * ( ( in_len / 8 ) - 1 ) - Plen;
        if ( padlen < 0 || padlen > 7 )
        {
            ret = MBEDTLS_ERR_KW_AUTH_FAILED;
            goto cleanup;
        }
        for( i = 0; i < (size_t)padlen; i++ )
        {
            if( output[ in_len - padlen + i ] != 0 )
            {
                ret = MBEDTLS_ERR_KW_AUTH_FAILED;
                goto cleanup;
            }
        }
        /*
         * shift output to point to P
         */

       memcpy( output, output + KW_SEMIBLOCK_LENGTH , Plen);
       memset( output + Plen, 0, KW_SEMIBLOCK_LENGTH + padlen );
       *out_len = padlen;
    }

cleanup:
    if( ret != 0 )
        mbedtls_platform_zeroize( output, in_len - 1);

    mbedtls_cipher_finish( &ctx->cipher_ctx, NULL, out_len );
    return( ret );
}

#endif /* !MBEDTLS_KW_ALT */

#if defined(MBEDTLS_SELF_TEST) && defined(MBEDTLS_AES_C)


int mbedtls_kw_self_test( int verbose )
{

    if( verbose != 0 )
        mbedtls_printf( "\n" );
    return( 0 );
}

#endif /* MBEDTLS_SELF_TEST && MBEDTLS_AES_C */

#endif /* MBEDTLS_KW_C */
