/**
 * \file padlock.h
 *
 *  Based on XySSL: Copyright (C) 2006-2008  Christophe Devine
 *
 *  Copyright (C) 2009  Paul Bakker <polarssl_maintainer at polarssl dot org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef POLARSSL_PADLOCK_H
#define POLARSSL_PADLOCK_H

#include "polarssl/aes.h"

#if defined(POLARSSL_HAVE_ASM) && defined(__GNUC__) && defined(__i386__)

#ifndef POLARSSL_HAVE_X86
#define POLARSSL_HAVE_X86
#endif

#define PADLOCK_RNG 0x000C
#define PADLOCK_ACE 0x00C0
#define PADLOCK_PHE 0x0C00
#define PADLOCK_PMM 0x3000

#define PADLOCK_ALIGN16(x) (unsigned long *) (16 + ((long) x & ~15))

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          PadLock detection routine
 *
 * \return         1 if CPU has support for the feature, 0 otherwise
 */
int padlock_supports( int feature );

/**
 * \brief          PadLock AES-ECB block en(de)cryption
 *
 * \param ctx      AES context
 * \param mode     AES_ENCRYPT or AES_DECRYPT
 * \param input    16-byte input block
 * \param output   16-byte output block
 *
 * \return         0 if success, 1 if operation failed
 */
int padlock_xcryptecb( aes_context *ctx,
                       int mode,
                       unsigned char input[16],
                       unsigned char output[16] );

/**
 * \brief          PadLock AES-CBC buffer en(de)cryption
 *
 * \param ctx      AES context
 * \param mode     AES_ENCRYPT or AES_DECRYPT
 * \param length   length of the input data
 * \param iv       initialization vector (updated after use)
 * \param input    buffer holding the input data
 * \param output   buffer holding the output data
 *
 * \return         0 if success, 1 if operation failed
 */
int padlock_xcryptcbc( aes_context *ctx,
                       int mode,
                       int length,
                       unsigned char iv[16],
                       unsigned char *input,
                       unsigned char *output );

#ifdef __cplusplus
}
#endif

#endif /* HAVE_X86  */

#endif /* padlock.h */
