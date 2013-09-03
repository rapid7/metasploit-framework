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
require 'msf/core/post/solaris/system'


class Metasploit3 < Msf::Post

	include Msf::Post::Common
	include Msf::Post::File
	include Msf::Post::Solaris::System

	def initialize(info={})
		super( update_info( info,
				'Name'          => 'Solaris Gather Configured Services',
				'Description'   => %q{ Post Module to enumerate services on a Solaris System},
				'License'       => MSF_LICENSE,
				'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
				'Platform'      => [ 'solaris' ],
				'SessionTypes'  => [ 'shell' ]
			))

	end

	# Run Method for when run command is issued
	def run
		distro = get_sysinfo
		store_loot("solaris.version", "text/plain", session, "Distro: #{distro[:hostname]}, Version: #{distro[:version]}, Kernel: #{distro[:kernel]}", "solaris_info.txt", "Solaris Version")

		# Print the info
		print_good("Info:")
		print_good("\t#{distro[:version]}")
		print_good("\t#{distro[:kernel]}")
		installed_pkg = get_services()
		pkg_loot = store_loot("solaris.services", "text/plain", session, installed_pkg, "configured_services.txt", "Solaris Configured Services")
		print_status("Service list saved to loot file: #{pkg_loot}")
		if datastore['VERBOSE']
			print_good("Services:")

			# Print the Packages
			installed_pkg.each_line do |p|
				print_good("\t#{p.chomp}")
			end
		end

	end

	def get_services()
		services_installed = ""
		services_installed = cmd_exec("/usr/bin/svcs -a")
		return services_installed
	end
end
