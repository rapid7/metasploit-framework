##
# ## This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
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
				'Name'          => 'Linux Find Installed AV, Firewalls, Etc',
				'Description'   => %q{
					This module tries to find certain installed applications.
					We are looking for anti-virus, rootkit detection, IDS/IPS,
					firewalls and other protection mechanisms.
				},
				'License'       => MSF_LICENSE,
				'Author'        =>
					[
						'ohdae <bindshell[at]live.com>',
					],
				'Version'       => '$Revision$',
				'Platform'      => [ 'linux' ],
				'SessionTypes'  => [ 'shell' ]
			))

	end

	def run
		distro = get_sysinfo

		print_good("Info:")
		print_good("\t#{distro[:version]}")
		print_good("\t#{distro[:kernel]}")
		
		#vprint_status("Finding installed applications...")
		#ruby = which('ruby')
		#save("Location", ruby)
		find_apps		
	
	end

	def save(msg, data, ctype="text/plain")
		ltype = "linux.find.apps"
		loot = store_loot(ltype, ctype, session, data, nil, msg)
		print_status("#{msg} stored in #{loot.to_s}")
	end

	def get_host
		case session.type
		when /meterpreter/
			host = sysinfo["Computer"]
		when /shell/
			host = session.shell_command_token("hostname").chomp
		end

		print_status("Running module against #{host}")

		return host
	end

	def which(cmd)
  		exts = ENV['PATHEXT'] ? ENV['PATHEXT'].split(';') : ['']
 		ENV['PATH'].split(::File::PATH_SEPARATOR).each do |path|
    			exts.each { |ext|
      				exe = "#{path}/#{cmd}#{ext}"
      				return exe if ::File.executable? exe
    			}
		end
  		return nil

	end

	def find_apps
		installed = []
		apps = ["truecrypt", "bulldog", "ufw", "iptables", "logrotate", "logwatch", 
               	"chkrootkit", "clamav", "snort", "tiger", "firestarter", "avast", "lynis",
               	"rkhunter", "tcpdump", "webmin", "jailkit", "pwgen", "proxychains", "bastille",
		 "psad", "wireshark", "nagios", "nagios", "apparmor"]

		for items in apps
			output = which(items)
			installed += [output] unless [output] == nil

		end
		save("Installed applications:", installed) unless installed == nil
	end
end
