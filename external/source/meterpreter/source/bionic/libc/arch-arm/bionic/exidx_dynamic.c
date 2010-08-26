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
typedef long unsigned int *_Unwind_Ptr;

/* Stubbed out in libdl and defined in the dynamic linker.
 * Same semantics as __gnu_Unwind_Find_exidx().
 */
extern _Unwind_Ptr dl_unwind_find_exidx(_Unwind_Ptr pc, int *pcount);

/* For a given PC, find the .so that it belongs to.
 * Returns the base address of the .ARM.exidx section
 * for that .so, and the number of 8-byte entries
 * in that section (via *pcount).
 *
 * libgcc declares __gnu_Unwind_Find_exidx() as a weak symbol, with
 * the expectation that libc will define it and call through to
 * a differently-named function in the dynamic linker.
 */
_Unwind_Ptr __gnu_Unwind_Find_exidx(_Unwind_Ptr pc, int *pcount)
{
    return dl_unwind_find_exidx(pc, pcount);
}
