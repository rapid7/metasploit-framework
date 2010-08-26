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

#include <machine/cpu-features.h>

    .text

    .global __memcmp16
    .type __memcmp16, %function
    .align 4

/*
 * Optimized memcmp16() for ARM9.
 * This would not be optimal on XScale or ARM11, where more prefetching
 * and use of PLD will be needed.
 * The 2 major optimzations here are
 * (1) The main loop compares 16 bytes at a time
 * (2) The loads are scheduled in a way they won't stall
 */

__memcmp16:
        .fnstart
        PLD         (r0, #0)
        PLD         (r1, #0)

        /* take of the case where length is nul or the buffers are the same */
        cmp         r0, r1
        cmpne       r2, #0
        moveq       r0, #0
        bxeq        lr

        /* since r0 hold the result, move the first source
         * pointer somewhere else
         */

        mov         r3, r0

         /* make sure we have at least 12 words, this simplify things below
          * and avoid some overhead for small blocks
          */

        cmp         r2, #12
        bpl         0f

        /* small blocks (less then 12 words) */
        PLD         (r0, #32)
        PLD         (r1, #32)

1:      ldrh        r0, [r3], #2
        ldrh        ip, [r1], #2
        subs        r0, r0, ip
        bxne        lr        
        subs        r2, r2, #1
        bne         1b
        bx          lr


        .save {r4, lr}
        /* save registers */
0:      stmfd       sp!, {r4, lr}
        
        /* align first pointer to word boundary */
        tst         r3, #2
        beq         0f
        
        ldrh        r0, [r3], #2
        ldrh        ip, [r1], #2
        sub         r2, r2, #1
        subs        r0, r0, ip
        /* restore registers and return */
        ldmnefd     sp!, {r4, lr}
        bxne        lr
        .fnend



0:      /* here the first pointer is aligned, and we have at least 3 words
         * to process.
         */

        /* see if the pointers are congruent */
        eor         r0, r3, r1
        ands        r0, r0, #2
        bne         5f

        /* congruent case, 16 half-words per iteration
         * We need to make sure there are at least 16+2 words left
         * because we effectively read ahead one long word, and we could
         * read past the buffer (and segfault) if we're not careful.
         */

        ldr         ip, [r1]
        subs        r2, r2, #(16 + 2)
        bmi         1f
        
0:
        PLD         (r3, #64)
        PLD         (r1, #64)
        ldr         r0, [r3], #4
        ldr         lr, [r1, #4]!
        eors        r0, r0, ip
        ldreq       r0, [r3], #4
        ldreq       ip, [r1, #4]!
        eoreqs      r0, r0, lr
        ldreq       r0, [r3], #4
        ldreq       lr, [r1, #4]!
        eoreqs      r0, r0, ip
        ldreq       r0, [r3], #4
        ldreq       ip, [r1, #4]!
        eoreqs      r0, r0, lr
        ldreq       r0, [r3], #4
        ldreq       lr, [r1, #4]!
        eoreqs      r0, r0, ip
        ldreq       r0, [r3], #4
        ldreq       ip, [r1, #4]!
        eoreqs      r0, r0, lr
        ldreq       r0, [r3], #4
        ldreq       lr, [r1, #4]!
        eoreqs      r0, r0, ip
        ldreq       r0, [r3], #4
        ldreq       ip, [r1, #4]!
        eoreqs      r0, r0, lr
        bne         2f        
        subs        r2, r2, #16
        bhs         0b

        /* do we have at least 2 words left? */
1:      adds        r2, r2, #(16 - 2 + 2)
        bmi         4f
        
        /* finish off 2 words at a time */
3:      ldr         r0, [r3], #4
        ldr         ip, [r1], #4
        eors        r0, r0, ip
        bne         2f
        subs        r2, r2, #2
        bhs         3b

        /* are we done? */
4:      adds        r2, r2, #2
        bne         8f
        /* restore registers and return */
        mov         r0, #0
        ldmfd       sp!, {r4, lr}
        bx          lr

2:      /* the last 2 words are different, restart them */
        ldrh        r0, [r3, #-4]
        ldrh        ip, [r1, #-4]
        subs        r0, r0, ip
        ldreqh      r0, [r3, #-2]
        ldreqh      ip, [r1, #-2]
        subeqs      r0, r0, ip
        /* restore registers and return */
        ldmfd       sp!, {r4, lr}
        bx          lr

        /* process the last few words */
8:      ldrh        r0, [r3], #2
        ldrh        ip, [r1], #2
        subs        r0, r0, ip
        bne         9f
        subs        r2, r2, #1
        bne         8b

9:      /* restore registers and return */
        ldmfd       sp!, {r4, lr}
        bx          lr


5:      /*************** non-congruent case ***************/

        /* align the unaligned pointer */
        bic         r1, r1, #3
        ldr         lr, [r1], #4
        sub         r2, r2, #8

6:
        PLD         (r3, #64)
        PLD         (r1, #64)
        mov         ip, lr, lsr #16
        ldr         lr, [r1], #4
        ldr         r0, [r3], #4
        orr         ip, ip, lr, lsl #16
        eors        r0, r0, ip
        moveq       ip, lr, lsr #16
        ldreq       lr, [r1], #4
        ldreq       r0, [r3], #4
        orreq       ip, ip, lr, lsl #16
        eoreqs      r0, r0, ip
        moveq       ip, lr, lsr #16
        ldreq       lr, [r1], #4
        ldreq       r0, [r3], #4
        orreq       ip, ip, lr, lsl #16
        eoreqs      r0, r0, ip
        moveq       ip, lr, lsr #16
        ldreq       lr, [r1], #4
        ldreq       r0, [r3], #4
        orreq       ip, ip, lr, lsl #16
        eoreqs      r0, r0, ip
        bne         7f
        subs        r2, r2, #8
        bhs         6b
        sub         r1, r1, #2
        /* are we done? */
        adds        r2, r2, #8
        moveq       r0, #0
        beq         9b
        /* finish off the remaining bytes */
        b           8b

7:      /* fix up the 2 pointers and fallthrough... */
        sub         r1, r1, #2
        b           2b
