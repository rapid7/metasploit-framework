##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
#   http://metasploit.com/framework/
##

require 'msf/core'
require 'rex'
require 'msf/core/post/common'
require 'msf/core/post/file'
require 'msf/core/post/linux/system'
require 'msf/core/post/linux/priv'

class Metasploit3 < Msf::Post

	include Msf::Post::Common
	include Msf::Post::File
	include Msf::Post::Linux::Priv
	include Msf::Post::Linux::System


	def initialize(info={})
		super( update_info( info,
				'Name'          => 'Linux Reboot',
				'Description'   => %q{
					This module reboots the system. Require root permissions.
				},
				'License'       => MSF_LICENSE,
				'Author'        =>
					[
						'Joshua D. Abraham <jabra[at]praetorian.com>',
					],
				'Platform'      => [ 'linux' ],
				'SessionTypes'  => [ 'shell' ]
			))
	end

	def run
		if is_root?	
			vcmd_exec("reboot")
		else 
			print_error("This module require root permissions.")
			return
		end
	end
end
