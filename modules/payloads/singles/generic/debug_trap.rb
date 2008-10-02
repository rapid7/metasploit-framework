##
# $Id: shell_bind_tcp.rb 4419 2007-02-18 00:10:39Z hdm $
##

##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##


require 'msf/core'
require 'msf/core/payload/generic'


module Metasploit3

	include Msf::Payload::Single

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'Generic x86 Debug Trap',
			'Version'       => '$Revision: 4419 $',
			'Description'   => 'Generate a debug trap in the target process',
			'Author'        => 'robert <robertmetasploit [at] gmail.com>',
			'Platform'	=> [ 'win', 'linux', 'bsd', 'solaris', 'bsdi', 'osx' ],
			'License'       => MSF_LICENSE,
			'Arch'		=> ARCH_X86,
			'Payload'	=> 
				{
					'Payload' => 
							"\xcc"
				}
			))
	end

end

   
