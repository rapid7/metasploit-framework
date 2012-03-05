# $Id$
##

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


class Metasploit3 < Msf::Post

	include Msf::Post::Common
	include Msf::Post::File
	include Msf::Post::Linux::System

	def initialize(info={})
		super( update_info( info,
				'Name'          => 'Linux Gather Configured Services',
				'Description'   => %q{ Post Module to enumerate Services on a Linux System},
				'License'       => MSF_LICENSE,
				'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
				'Version'       => '$Revision$',
				'Platform'      => [ 'linux' ],
				'SessionTypes'  => [ 'shell' ]
			))

	end

	# Run Method for when run command is issued
	def run
		distro = get_sysinfo
		store_loot("linux.version", "text/plain", session, "Distro: #{distro[:distro]}, Version: #{distro[:version]}, Kernel: #{distro[:kernel]}", "linux_info.txt", "Linux Version")

		# Print the info
		print_good("Info:")
		print_good("\t#{distro[:version]}")
		print_good("\t#{distro[:kernel]}")
		installed_pkg = get_services(distro[:distro])
		pkg_loot = store_loot("linux.services", "text/plain", session, installed_pkg, "configured_services.txt", "Linux Configured Services")
		print_status("Service list saved to loot file: #{pkg_loot}")
		if datastore['VERBOSE']
			print_good("Services:")

			# Print the Packages
			installed_pkg.each_line do |p|
				print_good("\t#{p.chomp}")
			end
		end

	end

	def get_services(distro)
		services_installed = ""
		if distro =~ /fedora|redhat|suse|mandrake|oracle|amazon/
			services_installed = cmd_exec("/sbin/chkconfig --list")
		elsif distro =~ /slackware/
			services_installed << "\nEnabled:\n*************************\n"
			services_installed << cmd_exec("ls -F /etc/rc.d | /bin/grep \'*$\'")
			services_installed << "\n\nDisabled:\n*************************\n"
			services_installed << cmd_exec("ls -F /etc/rc.d | /bin/grep \'[a-z0-9A-z]$\'")
		elsif distro =~ /ubuntu|debian/
			services_installed = cmd_exec("/usr/bin/service --status-all")
		elsif distro =~ /gentoo/
			services_installed = cmd_exec("/bin/rc-status --all")
		elsif distro =~ /arch/
			services_installed = cmd_exec("/bin/egrep '^DAEMONS' /etc/rc.conf")
		else
			print_error("Could not determine the Linux Distribution to get list of configured services")
		end
		return services_installed
	end
end

