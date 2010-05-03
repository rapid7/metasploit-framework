##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'

module Msf
module Payloads
module Singles

###
#
# This sample payload is designed to trigger a debugger exception via int3.
#
###
module Sample

	include Msf::Payload::Single

	def initialize(info = {})
		super(update_info(info,
			'Name'          => 'Debugger Trap',
			'Version'       => '$Revision$',
			'Description'   => 'Causes a debugger trap exception through int3',
			'Author'        => 'skape',
			'Platform'      => 'win',
			'Arch'          => ARCH_X86,
			'Payload'       =>
				{
					'Payload' => "\xcc"
				}
			))
	end

end

end
end
end
