# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/windows'

module Msf

###
#
# Implements arbitrary exit routines for Windows ARCH_X86_64 payloads
#
###

module Payload::Windows::Exitfunk_x64

  def asm_exitfunk(opts={})

    asm = "exitfunk:\n"

    case opts[:exitfunk]

    when 'seh'
      asm << %Q^
        push 0                ;
        pop rcx               ; set the exit function parameter
        mov ebx, #{"0x%.8x" % Msf::Payload::Windows.exit_types['seh']}
        mov r10d, ebx         ; place the correct EXITFUNK into r10d
        call rbp              ; SetUnhandledExceptionFilter(0)
        push 0                ;
        ret                   ; Return to NULL (crash)
      ^

    # On Windows Vista, Server 2008, and newer, it is not possible to call ExitThread
    # on WoW64 processes, instead we need to call RtlExitUserThread. This stub will
    # automatically generate the right code depending on the selected exit method.

    when 'thread'
      asm << %Q^
        mov ebx, #{"0x%.8x" % Msf::Payload::Windows.exit_types['thread']}
        mov r10d, 0x9DBD95A6  ; hash( "kernel32.dll", "GetVersion" )
        call rbp              ; GetVersion(); (AL will = major version and AH will = minor version)
        add rsp, 40           ; cleanup the default param space on stack
        cmp al, byte 6        ; If we are not running on Windows Vista, 2008 or 7
        jl short goodbye      ; Then just call the exit function...
        cmp bl, 0xE0          ; If we are trying a call to kernel32.dll!ExitThread on
                              ; Windows Vista, 2008 or 7...
        jne short goodbye     ;
        mov ebx, 0x6F721347   ; Then we substitute the EXITFUNK to that of ntdll.dll!RtlExitUserThread
      goodbye:                ; We now perform the actual call to the exit function
        push byte 0           ;
        pop rcx               ; set the exit function parameter
        mov r10d, ebx         ; place the correct EXITFUNK into r10d
        call rbp              ; call EXITFUNK( 0 );
      ^

    when 'process', nil
      asm << %Q^
        push 0                ;
        pop rcx               ; set the exit function parameter
        mov ebx, #{"0x%.8x" % Msf::Payload::Windows.exit_types['process']}
        mov r10d, ebx         ; place the correct EXITFUNK into r10d
        call rbp              ; ExitProcess(0)
      ^

    when 'sleep'
      asm << %Q^
        push 300000           ; 300 seconds
        pop rcx               ; set the sleep function parameter
        mov ebx, #{"0x%.8x" % Rex::Text.ror13_hash('Sleep')}
        mov r10d, ebx         ; place the correct EXITFUNK into r10d
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
