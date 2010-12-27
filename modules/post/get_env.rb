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
require 'rex'

class Metasploit3 < Msf::Post

	def initialize(info={})
		super( update_info( info,
			'Name'          => 'Get environment',
			'Description'   => %q{ Print out environment variables },
			'License'       => MSF_LICENSE,
			'Author'        => [ 'egypt' ],
			'Version'       => '$Revision$',
			'Platform'      => [ 'linux', 'windows' ],
			'SessionTypes'  => [ 'shell', 'meterpreter' ]
		))
	end

	def run
		case session.type
		when "shell"
			get_env_shell
		when "meterpreter"
			get_env_meterpreter
		end
	end

	def get_env_shell
		case session.platform
		when /unix|linux|bsd|bsdi|aix|solaris/
			output = session.shell_command_token("env")
		when /windows/
			output = session.shell_command_token("set")
		else
			# Don't know what it is, hope it's unix
			if session.respond_to? :shell_command_token_unix
				output = session.shell_command_token_unix("env")
			end
		end
		print_line output if output
	end

	def get_env_meterpreter
		case sysinfo["OS"]
		when /windows/i
			var_names = []
			var_names << registry_enumvals("HKEY_CURRENT_USER\\Volatile Environment")
			var_names << registry_enumvals("HKEY_CURRENT_USER\\Environment")
			var_names << registry_enumvals("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment")
			var_names.flatten.each do |v|
				print_line "#{v}=#{session.fs.file.expand_path("\%#{v}\%")}"
			end
		else
			print_status sysinfo["OS"]
			chan = session.sys.process.execute("/bin/sh -c env", nil, {"Channelized" => true})
			print_line chan.read
		end
	end

	def registry_enumvals(key)
		values = []
		begin
			vals = {}
			root_key, base_key = session.sys.registry.splitkey(key)
			open_key = session.sys.registry.open_key(root_key, base_key, KEY_READ)
			vals = open_key.enum_value
			vals.each { |val|
				values <<  val.name
			}
			open_key.close
		end
		return values
	end
end

