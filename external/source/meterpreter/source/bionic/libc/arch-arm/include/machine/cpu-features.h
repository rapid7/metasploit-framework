/*
 * Copyright (C) 2008 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#ifndef _ARM_MACHINE_CPU_FEATURES_H
#define _ARM_MACHINE_CPU_FEATURES_H

/* The purpose of this file is to define several macros corresponding
 * to CPU features that may or may not be available at build time on
 * on the target CPU.
 *
 * This is done to abstract us from the various ARM Architecture
 * quirks and alphabet soup.
 *
 * IMPORTANT: We have no intention to support anything below an ARMv4T !
 */

/* _ARM_ARCH_REVISION is a number corresponding to the ARM revision
 * we're going to support
 *
 * it looks like our toolchain doesn't define __ARM_ARCH__
 * so try to guess it.
 *
 *
 *
 */
#ifndef __ARM_ARCH__

#  if defined __ARM_ARCH_7__   || defined __ARM_ARCH_7A__ || \
      defined __ARM_ARCH_7R__  || defined __ARM_ARCH_7M__

#    define __ARM_ARCH__ 7

#  elif defined __ARM_ARCH_6__   || defined __ARM_ARCH_6J__ || \
      defined __ARM_ARCH_6K__  || defined __ARM_ARCH_6Z__ || \
      defined __ARM_ARCH_6KZ__ || defined __ARM_ARCH_6T2__
#
#    define __ARM_ARCH__ 6
#
#  elif defined __ARM_ARCH_5__ || defined __ARM_ARCH_5T__ || \
        defined __ARM_ARCH_5TE__ || defined __ARM_ARCH_5TEJ__
#
#    define __ARM_ARCH__ 5
#
#  elif defined __ARM_ARCH_4T__
#
#    define __ARM_ARCH__ 4
#
#  elif defined __ARM_ARCH_4__
#    error ARMv4 is not supported, please use ARMv4T at a minimum
#  else
#    error Unknown or unsupported ARM architecture
#  endif
#endif

/* experimental feature used to check that our ARMv4 workarounds
 * work correctly without a real ARMv4 machine */
#ifdef BIONIC_EXPERIMENTAL_FORCE_ARMV4
#  undef  __ARM_ARCH__
#  define __ARM_ARCH__  4
#endif

/* define __ARM_HAVE_5TE if we have the ARMv5TE instructions */
#if __ARM_ARCH__ > 5
#  define  __ARM_HAVE_5TE  1
#elif __ARM_ARCH__ == 5
#  if defined __ARM_ARCH_5TE__ || defined __ARM_ARCH_5TEJ__
#    define __ARM_HAVE_5TE  1
#  endif
#endif

/* instructions introduced in ARMv5 */
#if __ARM_ARCH__ >= 5
#  define  __ARM_HAVE_BLX  1
#  define  __ARM_HAVE_CLZ  1
#  define  __ARM_HAVE_LDC2 1
#  define  __ARM_HAVE_MCR2 1
#  define  __ARM_HAVE_MRC2 1
#  define  __ARM_HAVE_STC2 1
#endif

/* ARMv5TE introduces a few instructions */
#if __ARM_HAVE_5TE
#  define  __ARM_HAVE_PLD   1
#  define  __ARM_HAVE_MCRR  1
#  define  __ARM_HAVE_MRRC  1
#endif

/* define __ARM_HAVE_HALFWORD_MULTIPLY when half-word multiply instructions
 * this means variants of: smul, smulw, smla, smlaw, smlal
 */
#if __ARM_HAVE_5TE
#  define  __ARM_HAVE_HALFWORD_MULTIPLY  1
#endif

/* define __ARM_HAVE_PAIR_LOAD_STORE when 64-bit memory loads and stored
 * into/from a pair of 32-bit registers is supported throuhg 'ldrd' and 'strd'
 */
#if __ARM_HAVE_5TE
#  define  __ARM_HAVE_PAIR_LOAD_STORE 1
#endif

/* define __ARM_HAVE_SATURATED_ARITHMETIC is you have the saturated integer
 * arithmetic instructions: qdd, qdadd, qsub, qdsub
 */
#if __ARM_HAVE_5TE
#  define  __ARM_HAVE_SATURATED_ARITHMETIC 1
#endif

/* define __ARM_HAVE_PC_INTERWORK when a direct assignment to the
 * pc register will switch into thumb/ARM mode depending on bit 0
 * of the new instruction address. Before ARMv5, this was not the
 * case, and you have to write:
 *
 *     mov  r0, [<some address>]
 *     bx   r0
 *
 * instead of:
 *
 *     ldr  pc, [<some address>]
 *
 * note that this affects any instruction that explicitely changes the
 * value of the pc register, including ldm { ...,pc } or 'add pc, #offset'
 */
#if __ARM_ARCH__ >= 5
#  define __ARM_HAVE_PC_INTERWORK
#endif

/* define _ARM_HAVE_LDREX_STREX for ARMv6 and ARMv7 architecure to be
 * used in replacement of depricated swp instruction
 */
#if __ARM_ARCH__ >= 6
#  define _ARM_HAVE_LDREX_STREX
#endif


/* Assembly-only macros */

/* define a handy PLD(address) macro since the cache preload
 * is an optional opcode
 */
#if __ARM_HAVE_PLD
#  define  PLD(reg,offset)    pld    [reg, offset]
#else
#  define  PLD(reg,offset)    /* nothing */
#endif

#endif /* _ARM_MACHINE_CPU_FEATURES_H */
