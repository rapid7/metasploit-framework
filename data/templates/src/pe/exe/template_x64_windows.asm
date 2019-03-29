; Author: Stephen Fewer (stephen_fewer[at]harmonysecurity[dot]com)
; Architecture: x64
;
; Assemble and link with the following command:
; "C:\Program Files\Microsoft Visual Studio 9.0\VC\bin\x86_amd64\ml64" template_x64_windows.asm /link /subsystem:windows /defaultlib:"C:\Program Files\Microsoft SDKs\Windows\v6.0A\Lib\x64\kernel32.lib" /entry:main 

extrn ExitProcess : proc
extrn VirtualAlloc : proc

.code

	main proc 
		sub rsp, 40        ;
		mov r9, 40h        ; 
		mov r8, 3000h      ; 
		mov rdx, 4096      ; 
		xor rcx, rcx       ; 
		call VirtualAlloc  ; lpPayload = VirtualAlloc( NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
		mov rcx, 4096      ;
		mov rsi, payload   ;
		mov rdi, rax       ;
		rep movsb          ; memcpy( lpPayload, payload, 4096 );
		call rax           ; lpPayload();
		xor rcx, rcx       ;
		call ExitProcess   ; ExitProcess( 0 );
	main endp
	
	payload proc
		A byte 'PAYLOAD:'
		B db 4096-8 dup ( 0 )
	payload endp
end
