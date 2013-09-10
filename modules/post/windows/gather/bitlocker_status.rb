##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/post/common'

###
#
# This post module sample shows how we can execute a command on the compromised machine
#
###
class Metasploit4 < Msf::Post

	include Msf::Post::Common

	def initialize(info={})
		super(update_info(info,
			'Name'          => 'Show BitLocker status',
			'Description'   => %q{Post module to show Windows BitLocker drive encryption status. Applies To: Windows 7, Windows 8, Windows Server 2008 R2, Windows Server 2012},
			'License'       => MSF_LICENSE,
			'Author'        => [ 'Sam Gaudet <msf[at]sgaudet.com>'],
			'Platform'      => [ 'win'],
			'SessionTypes'  => [ "shell", "meterpreter" ]
		))
	end

	#
	# This post module runs a ipconfig command and returns the output
	#
	def run
		print_status("Checking BitLocker Drive Encryption")
		o = cmd_exec("manage-bde -status")
		print_line(o)
	end

end
