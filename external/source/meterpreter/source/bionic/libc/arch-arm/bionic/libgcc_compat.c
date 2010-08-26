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

/* This file contains dummy references to libgcc.a functions to force the
 * dynamic linker to copy their definition into the final libc.so binary.
 *
 * They are required to ensure backwards binary compatibility with
 * Android 1.5 and Android 1.6 system images. Some applications built
 * using the NDK require them to be here.
 *
 * Now, for a more elaborate description of the issue:
 *
 * libgcc.a is a compiler-specific library containing various helper
 * functions used to implement certain operations that are not necessarily
 * supported by the target CPU. For example, integer division doesn't have a
 * corresponding CPU instruction on ARMv5, and is instead implemented in the
 * compiler-generated machine code as a call to an __idiv helper function.
 *
 * Normally, one has to place libgcc.a in the link command used to generate
 * target binaries (shared libraries and executables) after all objects and
 * static libraries, but before dependent shared libraries, i.e. something
 * like:
 *         gcc <options> -o libfoo.so  foo.a libgcc.a -lc -lm
 *
 * This ensures that any helper function needed by the code in foo.a is copied
 * into the final libfoo.so. Unfortunately, the Android build system has been
 * using this instead:
 *
 *         gcc <options> -o libfoo.so foo.a -lc -lm libgcc.a
 *
 * The problem with this is that if one helper function needed by foo.a has
 * already been copied into libc.so or libm.so, then nothing will be copied
 * into libfoo.so. Instead, a symbol import definition will be added to it
 * so libfoo.so can directly call the one in libc.so at runtime.
 *
 * When changing toolchains for 2.0, the set of helper functions copied to
 * libc.so changed, which resulted in some native shared libraries generated
 * with the NDK to fail to load properly.
 *
 * The NDK has been fixed after 1.6_r1 to use the correct link command, so
 * any native shared library generated with it should now be safe from that
 * problem. On the other hand, existing shared libraries distributed with
 * applications that were generated with a previous version of the NDK
 * still need all 1.5/1.6 helper functions in libc.so and libn.so
 *
 * Final note: some of the functions below should really be in libm.so to
 *             completely reflect the state of 1.5/1.6 system images. However,
 *             since libm.so depends on libc.so, it's easier to put all of
 *             these in libc.so instead, since the dynamic linker will always
 *             search in libc.so before libm.so for dependencies.
 */

#define   COMPAT_FUNCTIONS_LIST \
    XX(__adddf3)             \
    XX(__addsf3)             \
    XX(__aeabi_cdcmpeq)      \
    XX(__aeabi_cdcmple)      \
    XX(__aeabi_cdrcmple)     \
    XX(__aeabi_d2f)          \
    XX(__aeabi_d2iz)         \
    XX(__aeabi_dadd)         \
    XX(__aeabi_dcmpeq)       \
    XX(__aeabi_dcmpge)       \
    XX(__aeabi_dcmpgt)       \
    XX(__aeabi_dcmple)       \
    XX(__aeabi_dcmplt)       \
    XX(__aeabi_dcmpun)       \
    XX(__aeabi_ddiv)         \
    XX(__aeabi_dmul)         \
    XX(__aeabi_drsub)        \
    XX(__aeabi_dsub)         \
    XX(__aeabi_f2d)          \
    XX(__aeabi_f2iz)         \
    XX(__aeabi_fadd)         \
    XX(__aeabi_fcmpun)       \
    XX(__aeabi_fdiv)         \
    XX(__aeabi_fmul)         \
    XX(__aeabi_frsub)        \
    XX(__aeabi_fsub)         \
    XX(__aeabi_i2d)          \
    XX(__aeabi_i2f)          \
    XX(__aeabi_l2d)          \
    XX(__aeabi_l2f)          \
    XX(__aeabi_lmul)         \
    XX(__aeabi_ui2d)         \
    XX(__aeabi_ui2f)         \
    XX(__aeabi_ul2d)         \
    XX(__aeabi_ul2f)         \
    XX(__cmpdf2)             \
    XX(__divdf3)             \
    XX(__divsf3)             \
    XX(__eqdf2)             \
    XX(__extendsfdf2)        \
    XX(__fixdfsi)            \
    XX(__fixsfsi)            \
    XX(__floatdidf)          \
    XX(__floatdisf)          \
    XX(__floatsidf)          \
    XX(__floatsisf)          \
    XX(__floatundidf)        \
    XX(__floatundisf)        \
    XX(__floatunsidf)        \
    XX(__floatunsisf)        \
    XX(__gedf2)              \
    XX(__gtdf2)              \
    XX(__ledf2)              \
    XX(__ltdf2)              \
    XX(__muldf3)             \
    XX(__muldi3)             \
    XX(__mulsf3)             \
    XX(__nedf2)              \
    XX(__subdf3)             \
    XX(__subsf3)             \
    XX(__truncdfsf2)         \
    XX(__unorddf2)           \
    XX(__unordsf2)           \

#define  XX(f)    extern void f(void);
COMPAT_FUNCTIONS_LIST
#undef XX

void  __bionic_libgcc_compat_hooks(void)
{
#define XX(f)    f();
COMPAT_FUNCTIONS_LIST
#undef XX
}
