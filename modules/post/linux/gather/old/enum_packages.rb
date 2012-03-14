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
				'Name'          => 'Linux Gather Installed Packages',
				'Description'   => %q{ Post Module to get installed packages on a Linux System},
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
		installed_pkg = get_pakages(distro[:distro])
		pkg_loot = store_loot("linux.packages", "text/plain", session, installed_pkg, "installed_packages.txt", "Linux Installed Packages")
		print_status("Package list saved to loot file: #{pkg_loot}")
		if datastore['VERBOSE']
			print_good("Packages:")

			# Print the Packages
			installed_pkg.each_line do |p|
				print_good("\t#{p.chomp}")
			end
		end

	end

	def get_pakages(distro)
		packages_installed = nil
		if distro =~ /fedora|redhat|suse|mandrake|oracle|amazon/
			packages_installed = cmd_exec("rpm -qa")
		elsif distro =~ /slackware/
			packages_installed = cmd_exec("ls /var/log/packages")
		elsif distro =~ /ubuntu|debian/
			packages_installed = cmd_exec("dpkg -l")
		elsif distro =~ /gentoo/
			packages_installed = cmd_exec("equery list")
		elsif distro =~ /arch/
			packages_installed = cmd_exec("/usr/bin/pacman -Q")
		else
			print_error("Could not determine package manager to get list of installed packages")
		end
		return packages_installed
	end
end
