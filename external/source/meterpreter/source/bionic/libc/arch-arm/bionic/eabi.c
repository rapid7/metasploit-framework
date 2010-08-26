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
#include <stddef.h>
#include <string.h>

extern int  __cxa_atexit(void (*)(void*), void*, void* );

/* Temporary hack: this variable should not be part of the C library
 * itself, but placed in the .bss section of each executable or
 * shared library instead.
 *
 * We keep it here temporarily until the build system has been
 * modified properly to use crtbegin_so.S and crtend_so.S when
 * generating shared libraries.
 *
 * It must be a 'weak' symbol to avoid conflicts with the definitions
 * that have been moved to crtbegin_static.S and crtbegin_dynamic.S
 *
 * For the record, it is used for static C++ object construction
 * and destruction. See http://www.codesourcery.com/public/cxx-abi/abi.html#dso-dtor
 */
void* __attribute__((weak)) __dso_handle;

/* The "C++ ABI for ARM" document states that static C++ constructors,
 * which are called from the .init_array, should manually call
 * __aeabi_atexit() to register static destructors explicitely.
 *
 * Note that 'dso_handle' is the address of a magic linker-generate
 * variable from the shared object that contains the constructor/destructor
 */

/* Make this a weak symbol to avoid a multiple definition error when linking
 * with libstdc++-v3.  */
int __attribute__((weak))
__aeabi_atexit (void *object, void (*destructor) (void *), void *dso_handle)
{
    return __cxa_atexit(destructor, object, dso_handle);
}


void __aeabi_memcpy8(void *dest, const void *src, size_t n) {
    memcpy(dest, src, n);
}

void __aeabi_memcpy4(void *dest, const void *src, size_t n) {
    memcpy(dest, src, n);
}

void __aeabi_memcpy(void *dest, const void *src, size_t n) {
    memcpy(dest, src, n);
}


void __aeabi_memmove8(void *dest, const void *src, size_t n) {
    memmove(dest, src, n);
}

void __aeabi_memmove4(void *dest, const void *src, size_t n) {
    memmove(dest, src, n);
}

void __aeabi_memmove(void *dest, const void *src, size_t n) {
    memmove(dest, src, n);
}

/*
 * __aeabi_memset has the order of its second and third arguments reversed. 
 *  This allows __aeabi_memclr to tail-call __aeabi_memset
 */
 
void __aeabi_memset8(void *dest, size_t n, int c) {
    memset(dest, c, n);
}

void __aeabi_memset4(void *dest, size_t n, int c) {
    memset(dest, c, n);
}

void __aeabi_memset(void *dest, size_t n, int c) {
    memset(dest, c, n);
}


void __aeabi_memclr8(void *dest, size_t n) {
    __aeabi_memset8(dest, n, 0);
}

void __aeabi_memclr4(void *dest, size_t n) {
    __aeabi_memset4(dest, n, 0);
}

void __aeabi_memclr(void *dest, size_t n) {
    __aeabi_memset(dest, n, 0);
}
