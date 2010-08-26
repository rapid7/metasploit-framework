# bionic/arch-x86/bionic/crtbegin_dynamic.S
#
# Copyright 2006, The Android Open Source Project
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of Google Inc. nor the names of its contributors may
#       be used to endorse or promote products derived from this software
#       without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY Google Inc. ``AS IS'' AND ANY EXPRESS OR 
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO 
# EVENT SHALL Google Inc. BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; 
# OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, 
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR 
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

	.text
	.align 4
	.type _start, @function
	.globl _start

# this is the small startup code that is first run when
# any executable that is dynamically-linked with Bionic
# runs.
#
# it's purpose is to call __libc_init with appropriate
# arguments, which are:
#
#    - the address of the raw data block setup by the Linux
#      kernel ELF loader
#
#    - address of an "onexit" function, not used on any
#      platform supported by Bionic
#
#    - address of the "main" function of the program. We
#      can't hard-code it in the adr pseudo instruction
#      so we use a tiny trampoline that will get relocated
#      by the dynamic linker before this code runs
#
#    - address of the constructor list
#
_start:	
        mov     %esp, %eax
        mov     $1f, %edx
        pushl   %edx
        mov     $0f, %edx
        pushl   %edx
        mov     $0, %edx
        pushl   %edx
        pushl   %eax
        call     __libc_init

0:
        jmp   main

1:  .long   __PREINIT_ARRAY__
    .long   __INIT_ARRAY__
    .long   __FINI_ARRAY__
    .long   __CTOR_LIST__
      
# the .ctors section contains a list of pointers to "constructor"
# functions that need to be called in order during C library initialization,
# just before the program is being run. This is a C++ requirement
#
# the last entry shall be 0, and is defined in crtend.S
#
	.section .preinit_array, "aw"
	.globl __PREINIT_ARRAY__
__PREINIT_ARRAY__:
	.long -1

	.section .init_array, "aw"
	.globl __INIT_ARRAY__
__INIT_ARRAY__:
	.long -1

	.section .fini_array, "aw"
	.globl __FINI_ARRAY__
__FINI_ARRAY__:
	.long -1

	.section .ctors, "aw"
	.globl __CTOR_LIST__
__CTOR_LIST__:
	.long -1

#include "__dso_handle.S"
