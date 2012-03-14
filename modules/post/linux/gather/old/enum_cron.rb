##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'
require 'msf/core/post/common'
require 'msf/core/post/file'
require 'msf/core/post/linux/priv'

class Metasploit3 < Msf::Post

	include Msf::Post::Common
	include Msf::Post::File
	include Msf::Post::Linux::Priv
	include Msf::Auxiliary::Report

	def initialize(info={})
		super( update_info( info,
				'Name'          => 'Linux Cron Job Enumeration',
				'Description'   => %q{
					This module lists cron jobs for each user on the machine and saves it to loot.
				},
				'License'       => MSF_LICENSE,
				'Author'        =>
					[
						'Stephen Haywood <averagesecurityguy[at]gmail.com>',
					],
				'Version'       => '$Revision$',
				'Platform'      => [ 'linux' ],
				'SessionTypes'  => [ "shell", "meterpreter" ]
			))
	end

	# Run Method for when run command is issued
	def run
		if is_root?
			print_status("Enumerating as root")
			users = execute("/bin/cat /etc/passwd | cut -d : -f 1").split("\n")
			cron_data = ""
			users.each do |user|
				cron_data += "*****Listing cron jobs for #{user}*****\n"
				cron_data += execute("crontab -u #{user} -l") + "\n\n"
			end
		else
			user = execute("/usr/bin/whoami")
			user.strip! if user
			print_status("Enumerating as #{user}")
			cron_data = "***** Listing cron jobs for #{user} *****\n\n"
			cron_data += execute("crontab -l")
		end

		# Save cron data to loot
		save("Cron jobs", cron_data)

	end

	# Save enumerated data
	def save(msg, data, ctype="text/plain")
		ltype = "linux.enum.cron"
		loot = store_loot(ltype, ctype, session, data, nil, msg)
		print_status("#{msg} stored in #{loot.to_s}")
	end

	def execute(cmd)
		vprint_status("Execute: #{cmd}")
		output = cmd_exec(cmd)
		return output
	end

end

