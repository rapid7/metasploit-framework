# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/windows'
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
=======
>>>>>>> origin/pod/metasploit-api/_index.html
=======
>>>>>>> origin/pod/metasploit-excellent.mp3

module Msf

=======
module Msf


<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> rapid7/feature/complex-payloads
=======
module Msf


>>>>>>> origin/feature/complex-payloads
=======
<<<<<<< HEAD
=======
>>>>>>> origin/msf-complex-payloads
<<<<<<< HEAD
<<<<<<< HEAD
module Msf

=======
<<<<<<< HEAD
=======
>>>>>>> feature/complex-payloads
=======
>>>>>>> origin/pod/metasploit-api/_index.html
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
module Msf

=======

module Msf
>>>>>>> rapid7/master
=======

module Msf
>>>>>>> rapid7/master
<<<<<<< HEAD
>>>>>>> origin/payload-generator.rb
=======

module Msf
>>>>>>> rapid7/master
=======

module Msf
>>>>>>> rapid7/master
=======

module Msf
>>>>>>> rapid7/master
=======
>>>>>>> origin/pod/metasploit-api/_index.html
=======

module Msf
>>>>>>> rapid7/master
=======

module Msf
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> rapid7/master

<<<<<<< HEAD
>>>>>>> origin/msf-complex-payloads
=======
>>>>>>> origin/msf-complex-payloads
=======
>>>>>>> master
=======

module Msf
>>>>>>> master
=======
>>>>>>> rapid7/master
>>>>>>> origin/pod/metasploit-api/_index.html
=======

module Msf
>>>>>>> rapid7/master

<<<<<<< HEAD
>>>>>>> origin/payload-generator.rb
=======
>>>>>>> msf-complex-payloads
>>>>>>> origin/pod/metasploit-api/_index.html
=======
>>>>>>> feature/complex-payloads
>>>>>>> origin/pod/metasploit-excellent.mp3
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
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
=======
<<<<<<< HEAD
=======
>>>>>>> origin/msf-complex-payloads
=======
=======
>>>>>>> 4.11.2_release_pre-rails4
>>>>>>> origin/pod/metasploit-api/_index.html
=======
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> origin/payload-generator.rb
<<<<<<< HEAD
<<<<<<< HEAD
=======
>>>>>>> origin/pod/metasploit-api/_index.html
          mov ebx, #{"0x%.8x" % Msf::Payload::Windows.exit_types['seh']}
          push.i8 0              ; push the exit function parameter
          push ebx               ; push the hash of the exit function
          call ebp               ; SetUnhandledExceptionFilter(0)
          push.i8 0
          ret                    ; Return to NULL (crash)
        ^
=======
=======
>>>>>>> rapid7/master
=======
>>>>>>> rapid7/master
=======
>>>>>>> rapid7/master
=======
>>>>>>> rapid7/master
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> origin/msf-complex-payloads
=======
>>>>>>> origin/msf-complex-payloads
=======
=======
>>>>>>> rapid7/master
=======
>>>>>>> master
=======
>>>>>>> master
=======
>>>>>>> rapid7/master
>>>>>>> origin/payload-generator.rb
=======
>>>>>>> msf-complex-payloads
>>>>>>> origin/pod/metasploit-api/_index.html
=======
=======
>>>>>>> 4.11.2_release_pre-rails4
>>>>>>> origin/pod/metasploit-excellent.mp3
        mov ebx, 0x#{Msf::Payload::Windows.exit_types['seh'].to_s(16)}
        push.i8 0              ; push the exit function parameter
        push ebx               ; push the hash of the exit function
        call ebp               ; SetUnhandledExceptionFilter(0)
        push.i8 0
        ret                    ; Return to NULL (crash)
      ^
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
=======
=======
>>>>>>> origin/feature/complex-payloads
=======
=======
>>>>>>> origin/pod/metasploit-api/_index.html
=======
=======
>>>>>>> origin/pod/metasploit-excellent.mp3
          mov ebx, #{"0x%.8x" % Msf::Payload::Windows.exit_types['seh']}
          push.i8 0              ; push the exit function parameter
          push ebx               ; push the hash of the exit function
          call ebp               ; SetUnhandledExceptionFilter(0)
          push.i8 0
          ret                    ; Return to NULL (crash)
        ^
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> rapid7/feature/complex-payloads
=======
>>>>>>> origin/feature/complex-payloads
=======
<<<<<<< HEAD
=======
>>>>>>> origin/msf-complex-payloads
=======
>>>>>>> feature/complex-payloads
=======
>>>>>>> 4.11.2_release_pre-rails4
>>>>>>> origin/pod/metasploit-api/_index.html
=======
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> origin/payload-generator.rb
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
=======
>>>>>>> origin/pod/metasploit-api/_index.html
>>>>>>> rapid7/master
=======
>>>>>>> rapid7/master
=======
>>>>>>> rapid7/master
=======
>>>>>>> rapid7/master
=======
>>>>>>> rapid7/master
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> origin/msf-complex-payloads
=======
>>>>>>> origin/msf-complex-payloads
=======
=======
>>>>>>> rapid7/master
=======
>>>>>>> master
=======
>>>>>>> master
=======
>>>>>>> rapid7/master
>>>>>>> origin/payload-generator.rb
=======
>>>>>>> msf-complex-payloads
>>>>>>> origin/pod/metasploit-api/_index.html
=======
>>>>>>> feature/complex-payloads
=======
>>>>>>> 4.11.2_release_pre-rails4
>>>>>>> origin/pod/metasploit-excellent.mp3

    # On Windows Vista, Server 2008, and newer, it is not possible to call ExitThread
    # on WoW64 processes, instead we need to call RtlExitUserThread. This stub will
    # automatically generate the right code depending on the selected exit method.

    when 'thread'
      asm << %Q^
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
=======
<<<<<<< HEAD
=======
>>>>>>> origin/msf-complex-payloads
=======
=======
>>>>>>> 4.11.2_release_pre-rails4
>>>>>>> origin/pod/metasploit-api/_index.html
=======
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> origin/payload-generator.rb
<<<<<<< HEAD
<<<<<<< HEAD
=======
>>>>>>> origin/pod/metasploit-api/_index.html
          mov ebx, #{"0x%.8x" % Msf::Payload::Windows.exit_types['thread']}
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
          mov ebx, #{"0x%.8x" % Msf::Payload::Windows.exit_types['process']}
          push.i8 0              ; push the exit function parameter
          push ebx               ; push the hash of the exit function
          call ebp               ; ExitProcess(0)
        ^

    when 'sleep'
      asm << %Q^
          mov ebx, #{"0x%.8x" % Rex::Text.ror13_hash('Sleep')}
          push 300000            ; 300 seconds
          push ebx               ; push the hash of the function
          call ebp               ; Sleep(300000)
          jmp exitfunk           ; repeat
        ^
=======
=======
>>>>>>> rapid7/master
=======
>>>>>>> rapid7/master
=======
>>>>>>> rapid7/master
=======
>>>>>>> rapid7/master
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> origin/msf-complex-payloads
=======
>>>>>>> origin/msf-complex-payloads
=======
=======
>>>>>>> rapid7/master
=======
>>>>>>> master
=======
>>>>>>> master
=======
>>>>>>> rapid7/master
>>>>>>> origin/payload-generator.rb
=======
>>>>>>> msf-complex-payloads
>>>>>>> origin/pod/metasploit-api/_index.html
=======
=======
>>>>>>> 4.11.2_release_pre-rails4
>>>>>>> origin/pod/metasploit-excellent.mp3
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
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
=======
>>>>>>> msf-complex-payloads
=======

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
=======
          mov ebx, #{"0x%.8x" % Msf::Payload::Windows.exit_types['thread']}
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
=======
>>>>>>> 4.11.2_release_pre-rails4
>>>>>>> origin/pod/metasploit-excellent.mp3

    when 'process', nil
      asm << %Q^
        mov ebx, 0x#{Msf::Payload::Windows.exit_types['process'].to_s(16)}
        push.i8 0              ; push the exit function parameter
        push ebx               ; push the hash of the exit function
        call ebp               ; ExitProcess(0)
      ^

    when 'sleep'
      asm << %Q^
<<<<<<< HEAD
          mov ebx, #{"0x%.8x" % Rex::Text.ror13_hash('Sleep')}
          push 300000            ; 300 seconds
          push ebx               ; push the hash of the function
          call ebp               ; Sleep(300000)
          jmp exitfunk           ; repeat
        ^
>>>>>>> feature/complex-payloads
=======
        mov ebx, #{Rex::Text.block_api_hash('kernel32.dll', 'Sleep')}
        push 300000            ; 300 seconds
        push ebx               ; push the hash of the function
        call ebp               ; Sleep(300000)
        jmp exitfunk           ; repeat
      ^
<<<<<<< HEAD
<<<<<<< HEAD
=======
          mov ebx, #{"0x%.8x" % Msf::Payload::Windows.exit_types['thread']}
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
=======
>>>>>>> 4.11.2_release_pre-rails4

    when 'process', nil
      asm << %Q^
        mov ebx, 0x#{Msf::Payload::Windows.exit_types['process'].to_s(16)}
        push.i8 0              ; push the exit function parameter
        push ebx               ; push the hash of the exit function
        call ebp               ; ExitProcess(0)
      ^

    when 'sleep'
      asm << %Q^
<<<<<<< HEAD
          mov ebx, #{"0x%.8x" % Rex::Text.ror13_hash('Sleep')}
          push 300000            ; 300 seconds
          push ebx               ; push the hash of the function
          call ebp               ; Sleep(300000)
          jmp exitfunk           ; repeat
        ^
>>>>>>> feature/complex-payloads
=======
        mov ebx, #{Rex::Text.block_api_hash('kernel32.dll', 'Sleep')}
        push 300000            ; 300 seconds
        push ebx               ; push the hash of the function
        call ebp               ; Sleep(300000)
        jmp exitfunk           ; repeat
      ^
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
=======
=======
>>>>>>> origin/feature/complex-payloads
          mov ebx, #{"0x%.8x" % Msf::Payload::Windows.exit_types['thread']}
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
          mov ebx, #{"0x%.8x" % Msf::Payload::Windows.exit_types['process']}
          push.i8 0              ; push the exit function parameter
          push ebx               ; push the hash of the exit function
          call ebp               ; ExitProcess(0)
        ^

    when 'sleep'
      asm << %Q^
          mov ebx, #{"0x%.8x" % Rex::Text.ror13_hash('Sleep')}
          push 300000            ; 300 seconds
          push ebx               ; push the hash of the function
          call ebp               ; Sleep(300000)
          jmp exitfunk           ; repeat
        ^
<<<<<<< HEAD
>>>>>>> rapid7/feature/complex-payloads
=======
>>>>>>> origin/feature/complex-payloads
=======
<<<<<<< HEAD
=======
>>>>>>> origin/msf-complex-payloads
=======
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> origin/payload-generator.rb
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> rapid7/master
=======
=======
>>>>>>> 4.11.2_release_pre-rails4
=======
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> origin/pod/metasploit-api/_index.html
>>>>>>> rapid7/master
=======
>>>>>>> rapid7/master
=======
>>>>>>> rapid7/master
=======
>>>>>>> rapid7/master
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> origin/msf-complex-payloads
=======
>>>>>>> origin/msf-complex-payloads
=======
=======
>>>>>>> rapid7/master
=======
>>>>>>> master
=======
>>>>>>> master
=======
>>>>>>> rapid7/master
>>>>>>> origin/payload-generator.rb
=======
=======
>>>>>>> rapid7/master
>>>>>>> msf-complex-payloads
>>>>>>> origin/pod/metasploit-api/_index.html
=======
>>>>>>> 4.11.2_release_pre-rails4
>>>>>>> origin/pod/metasploit-excellent.mp3
    else
      # Do nothing and continue after the end of the shellcode
    end

    asm
  end


end

end

