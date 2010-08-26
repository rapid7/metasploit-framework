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

    .global memcmp
    .type memcmp, %function
    .align 4

/*
 * Optimized memcmp() for ARM9.
 * This would not be optimal on XScale or ARM11, where more prefetching
 * and use of PLD will be needed.
 * The 2 major optimzations here are
 * (1) The main loop compares 16 bytes at a time
 * (2) The loads are scheduled in a way they won't stall
 */

memcmp:
        .fnstart
        PLD         (r0, #0)
        PLD         (r1, #0)

        /* take of the case where length is 0 or the buffers are the same */
        cmp         r0, r1
        cmpne       r2, #0
        moveq       r0, #0
        bxeq        lr

        .save {r4, lr}
        /* save registers */
        stmfd       sp!, {r4, lr}
        
        PLD         (r0, #32)
        PLD         (r1, #32)

        /* since r0 hold the result, move the first source
         * pointer somewhere else
         */
         
         mov        r4, r0
         
         /* make sure we have at least 8+4 bytes, this simplify things below
          * and avoid some overhead for small blocks
          */
         cmp        r2, #(8+4)
         bmi        8f
        
        /* align first pointer to word boundary
         * offset = -src & 3
         */
        rsb         r3, r4, #0
        ands        r3, r3, #3
        beq         0f

        /* align first pointer  */
        sub         r2, r2, r3
1:      ldrb        r0, [r4], #1
        ldrb        ip, [r1], #1
        subs        r0, r0, ip
        bne         9f
        subs        r3, r3, #1
        bne         1b


0:      /* here the first pointer is aligned, and we have at least 4 bytes
         * to process.
         */

        /* see if the pointers are congruent */
        eor         r0, r4, r1
        ands        r0, r0, #3
        bne         5f

        /* congruent case, 32 bytes per iteration
         * We need to make sure there are at least 32+4 bytes left
         * because we effectively read ahead one word, and we could
         * read past the buffer (and segfault) if we're not careful.
         */

        ldr         ip, [r1]
        subs        r2, r2, #(32 + 4)
        bmi         1f
        
0:      PLD         (r4, #64)
        PLD         (r1, #64)
        ldr         r0, [r4], #4
        ldr         lr, [r1, #4]!
        eors        r0, r0, ip
        ldreq       r0, [r4], #4
        ldreq       ip, [r1, #4]!
        eoreqs      r0, r0, lr
        ldreq       r0, [r4], #4
        ldreq       lr, [r1, #4]!
        eoreqs      r0, r0, ip
        ldreq       r0, [r4], #4
        ldreq       ip, [r1, #4]!
        eoreqs      r0, r0, lr
        ldreq       r0, [r4], #4
        ldreq       lr, [r1, #4]!
        eoreqs      r0, r0, ip
        ldreq       r0, [r4], #4
        ldreq       ip, [r1, #4]!
        eoreqs      r0, r0, lr
        ldreq       r0, [r4], #4
        ldreq       lr, [r1, #4]!
        eoreqs      r0, r0, ip
        ldreq       r0, [r4], #4
        ldreq       ip, [r1, #4]!
        eoreqs      r0, r0, lr
        bne         2f        
        subs        r2, r2, #32
        bhs         0b

        /* do we have at least 4 bytes left? */
1:      adds        r2, r2, #(32 - 4 + 4)
        bmi         4f
        
        /* finish off 4 bytes at a time */
3:      ldr         r0, [r4], #4
        ldr         ip, [r1], #4
        eors        r0, r0, ip
        bne         2f
        subs        r2, r2, #4
        bhs         3b

        /* are we done? */
4:      adds        r2, r2, #4
        moveq       r0, #0
        beq         9f

        /* finish off the remaining bytes */
        b           8f

2:      /* the last 4 bytes are different, restart them */
        sub         r4, r4, #4
        sub         r1, r1, #4
        mov         r2, #4

        /* process the last few bytes */
8:      ldrb        r0, [r4], #1
        ldrb        ip, [r1], #1
        // stall
        subs        r0, r0, ip
        bne         9f
        subs        r2, r2, #1
        bne         8b

9:      /* restore registers and return */
        ldmfd       sp!, {r4, lr}
        bx          lr
        .fnend





5:      /*************** non-congruent case ***************/
        and         r0, r1, #3      
        cmp         r0, #2
        bne         4f

        /* here, offset is 2 (16-bits aligned, special cased) */
        
        /* make sure we have at least 16 bytes to process */
        subs        r2, r2, #16
        addmi       r2, r2, #16
        bmi         8b

        /* align the unaligned pointer */
        bic         r1, r1, #3
        ldr         lr, [r1], #4

6:      PLD         (r1, #64)
        PLD         (r4, #64)
        mov         ip, lr, lsr #16
        ldr         lr, [r1], #4
        ldr         r0, [r4], #4
        orr         ip, ip, lr, lsl #16
        eors        r0, r0, ip
        moveq       ip, lr, lsr #16
        ldreq       lr, [r1], #4
        ldreq       r0, [r4], #4
        orreq       ip, ip, lr, lsl #16
        eoreqs      r0, r0, ip
        moveq       ip, lr, lsr #16
        ldreq       lr, [r1], #4
        ldreq       r0, [r4], #4
        orreq       ip, ip, lr, lsl #16
        eoreqs      r0, r0, ip
        moveq       ip, lr, lsr #16
        ldreq       lr, [r1], #4
        ldreq       r0, [r4], #4
        orreq       ip, ip, lr, lsl #16
        eoreqs      r0, r0, ip
        bne         7f
        subs        r2, r2, #16
        bhs         6b
        sub         r1, r1, #2
        /* are we done? */
        adds        r2, r2, #16
        moveq       r0, #0
        beq         9b
        /* finish off the remaining bytes */
        b           8b

7:      /* fix up the 2 pointers and fallthrough... */
        sub         r1, r1, #(4+2)
        sub         r4, r4, #4
        mov         r2, #4
        b           8b


4:      /*************** offset is 1 or 3 (less optimized) ***************/

		stmfd		sp!, {r5, r6, r7}

        // r5 = rhs
        // r6 = lhs
        // r7 = scratch

        mov         r5, r0, lsl #3		/* r5 = right shift */
        rsb         r6, r5, #32         /* r6 = left shift */

        /* align the unaligned pointer */
        bic         r1, r1, #3
        ldr         r7, [r1], #4
        sub         r2, r2, #8

6:      mov         ip, r7, lsr r5
        ldr         r7, [r1], #4
        ldr         r0, [r4], #4
        orr         ip, ip, r7, lsl r6
        eors        r0, r0, ip
        moveq       ip, r7, lsr r5
        ldreq       r7, [r1], #4
        ldreq       r0, [r4], #4
        orreq       ip, ip, r7, lsl r6
        eoreqs      r0, r0, ip
        bne         7f
        subs        r2, r2, #8
        bhs         6b

        sub         r1, r1, r6, lsr #3
		ldmfd       sp!, {r5, r6, r7}

        /* are we done? */
        adds        r2, r2, #8
        moveq       r0, #0
        beq         9b

        /* finish off the remaining bytes */
        b           8b

7:      /* fix up the 2 pointers and fallthrough... */
        sub         r1, r1, #4
        sub         r1, r1, r6, lsr #3
        sub         r4, r4, #4
        mov         r2, #4
		ldmfd		sp!, {r5, r6, r7}
        b           8b
