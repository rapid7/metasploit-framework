# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/windows'

module Msf

###
#
# Implements arbitrary exit routines for Windows ARCH_X86 payloads
#
###

module Payload::Windows::Exitfunk

  def asm_exitfunk(opts={})

    asm = "exitfunk:\n"

    case opts[:exitfunk]

    when 'seh'
      asm << %Q^
        mov ebx, 0x#{Msf::Payload::Windows.exit_types['seh'].to_s(16)}
        push.i8 0              ; push the exit function parameter
        push ebx               ; push the hash of the exit function
        call ebp               ; SetUnhandledExceptionFilter(0)
        push.i8 0
        ret                    ; Return to NULL (crash)
      ^

    # On Windows Vista, Server 2008, and newer, it is not possible to call ExitThread
    # on WoW64 processes, instead we need to call RtlExitUserThread. This stub will
    # automatically generate the right code depending on the selected exit method.

    when 'thread'
      asm << %Q^
        mov ebx, 0x#{Msf::Payload::Windows.exit_types['thread'].to_s(16)}
        push 0x9DBD95A6        ; hash( "kernel32.dll", "GetVersion" )
        call ebp               ; GetVersion(); (AL will = major version and AH will = minor version)
        cmp al, 6              ; If we are not running on Windows Vista, 2008 or 7
        jl exitfunk_goodbye    ; Then just call the exit function...
        cmp bl, 0xE0           ; If we are trying a call to kernel32.dll!ExitThread on Windows Vista, 2008 or 7...
        jne exitfunk_goodbye   ;
        mov ebx, 0x6F721347    ; Then we substitute the EXITFUNK to that of ntdll.dll!RtlExitUserThread
      exitfunk_goodbye:        ; We now perform the actual call to the exit function
        push.i8 0              ; push the exit function parameter
        push ebx               ; push the hash of the exit function
        call ebp               ; call ExitThread(0) || RtlExitUserThread(0)
      ^

    when 'process', nil
      asm << %Q^
        mov ebx, 0x#{Msf::Payload::Windows.exit_types['process'].to_s(16)}
        push.i8 0              ; push the exit function parameter
        push ebx               ; push the hash of the exit function
        call ebp               ; ExitProcess(0)
      ^

    when 'sleep'
      asm << %Q^
        mov ebx, #{Rex::Text.block_api_hash('kernel32.dll', 'Sleep')}
        push 300000            ; 300 seconds
        push ebx               ; push the hash of the function
        call ebp               ; Sleep(300000)
        jmp exitfunk           ; repeat
      ^
    else
      # Do nothing and continue after the end of the shellcode
    end

    asm
  end


end

end

