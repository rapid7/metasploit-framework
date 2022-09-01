;-----------------------------------------------------------------------------;
; Author: Stephen Fewer (stephen_fewer[at]harmonysecurity[dot]com)
; Compatible: Windows 7, 2008, Vista, 2003, XP
; Architecture: wow64
; Version: 1.0 (Jan 2010)
; Size: 75 bytes
; Build: >build.py executex64
;-----------------------------------------------------------------------------;

; A simple function to execute native x64 code from a wow64 (x86) process. 
; Can be called from C using the following prototype:
;     typedef DWORD (WINAPI * EXECUTEX64)( X64FUNCTION pFunction, DWORD dwParameter );
; The native x64 function you specify must be in the following form (as well as being x64 code):
;     typedef BOOL (WINAPI * X64FUNCTION)( DWORD dwParameter );

; Clobbers: EAX, ECX and EDX (ala the normal stdcall calling convention)
; Un-Clobbered: EBX, ESI, EDI, ESP and EBP can be expected to remain un-clobbered.

[BITS 32]

WOW64_CODE_SEGMENT	EQU 0x23
X64_CODE_SEGMENT	EQU 0x33

start:
	push ebp 								; prologue, save EBP...
	mov ebp, esp							; and create a new stack frame
	push esi								; save the registers we shouldn't clobber
	push edi								;
	mov esi, [ebp+8]						; ESI = pFunction
	mov ecx, [ebp+12]						; ECX = dwParameter
	call delta								;
delta:
	pop eax									;
	add eax, (native_x64-delta)				; get the address of native_x64
	
	sub esp, 8								; alloc some space on stack for far jump
	mov edx, esp							; EDX will be pointer our far jump
	mov dword [edx+4], X64_CODE_SEGMENT		; set the native x64 code segment
	mov dword [edx], eax					; set the address we want to jump to (native_x64)
	
	call go_all_native						; perform the transition into native x64 and return here when done.
	
	mov ax, ds								; fixes an elusive bug on AMD CPUs, http://blog.rewolf.pl/blog/?p=1484
	mov ss, ax								; found and fixed by ReWolf, incorporated by RaMMicHaeL
	
	add esp, (8+4+8)						; remove the 8 bytes we allocated + the return address which was never popped off + the qword pushed from native_x64
	pop edi									; restore the clobbered registers
	pop esi									;
	pop ebp									; restore EBP
	retn (4*2)								; return to caller (cleaning up our two function params)
	
go_all_native:
	mov edi, [esp]							; EDI is the wow64 return address
	jmp dword far [edx]						; perform the far jump, which will return to the caller of go_all_native
	
native_x64:
[BITS 64]									; we are now executing native x64 code...
	xor rax, rax							; zero RAX
	push rdi								; save RDI (EDI being our wow64 return address)
	call rsi								; call our native x64 function (the param for our native x64 function is allready in RCX)
	pop rdi									; restore RDI (EDI being our wow64 return address)
	push rax								; simply push it to alloc some space
	mov dword [rsp+4], WOW64_CODE_SEGMENT	; set the wow64 code segment 
	mov dword [rsp], edi					; set the address we want to jump to (the return address from the go_all_native call)
	jmp dword far [rsp]						; perform the far jump back to the wow64 caller...
