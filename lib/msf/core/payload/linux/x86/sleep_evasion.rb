module Msf::Payload::Linux::X86::SleepEvasion

  def sleep_evasion(opts = {})
    seconds = opts[:seconds] || rand(60)
    asm = <<-ASM
      ; nanosleep(&timespec, NULL)
      push 0              ; timespec.tv_nsec = 0
      push #{seconds}     ; timespec.tv_sec = <seconds>
      mov ebx, esp        ; ebx -> timespec on stack
      xor ecx, ecx        ; ecx = NULL (remaining time pointer)
      mov eax, 162        ; syscall number for nanosleep (0xa2)
      int 0x80            ; invoke syscall
      add esp, 8          ; restore stack
      ; execution continues to appended payload
    ASM

    Metasm::Shellcode.assemble(Metasm::X86.new, asm).encode_string
  end

end