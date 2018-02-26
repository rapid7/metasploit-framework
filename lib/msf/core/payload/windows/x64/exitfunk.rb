# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/windows'

module Msf

###
#
# Implements arbitrary exit routines for Windows ARCH_X64 payloads
#
###

module Payload::Windows::Exitfunk_x64

  def asm_exitfunk(opts={})

    asm = %Q^
      exitfunk:
        pop rax               ; won't be returning, realign the stack with a pop
    ^

    case opts[:exitfunk]

    when 'seh'
      asm << %Q^
        push 0                ;
        pop rcx               ; set the exit function parameter
        mov ebx, 0x#{Msf::Payload::Windows.exit_types['seh'].to_s(16)}
        mov r10d, ebx         ; place the correct EXITFUNK into r10d
        call rbp              ; SetUnhandledExceptionFilter(0)
        push 0                ;
        ret                   ; Return to NULL (crash)
      ^

    when 'thread'
      asm << %Q^
        push 0                ;
        pop rcx               ; set the exit function parameter
        mov ebx, 0x#{Msf::Payload::Windows.exit_types['thread'].to_s(16)}
        mov r10d, ebx         ; place the correct EXITFUNK into r10d
        call rbp              ; call EXITFUNK( 0 );
      ^

    when 'process', nil
      asm << %Q^
        push 0                ;
        pop rcx               ; set the exit function parameter
        mov r10, #{Rex::Text.block_api_hash('kernel32.dll', 'ExitProcess')}
        call rbp              ; ExitProcess(0)
      ^

    when 'sleep'
      asm << %Q^
        push 300000           ; 300 seconds
        pop rcx               ; set the sleep function parameter
        mov r10, #{Rex::Text.block_api_hash('kernel32.dll', 'Sleep')}
        call rbp              ; Sleep(30000)
        jmp exitfunk          ; repeat
      ^

    else
      # Do nothing and continue after the end of the shellcode
    end

    asm
  end

end

end
