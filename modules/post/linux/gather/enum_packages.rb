# $Id$
##

##
# ## This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'rex'
require 'msf/core/post/common'
require 'msf/core/post/file'


class Metasploit3 < Msf::Post

	include Msf::Post::Common
	include Msf::Post::File


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
		register_options(
			[
				OptBool.new('VERBOSE', [false, 'Show list of Packages.', false]),
			], self.class)

	end

	# Run Method for when run command is issued
	def run
		distro = linux_ver
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

	def linux_ver
		system_data = {}
		etc_files = cmd_exec("ls /etc").split()
		if etc_files.include?("debian_version")
			kernel_version = cmd_exec("uname -a")
			if kernel_version =~ /Ubuntu/
				print_good("This appears to be a Ubuntu Based System")
				version = read_file("/etc/issue").gsub(/\n|\\n|\\l/,'')
				system_data[:distro] = "ubuntu"
				system_data[:version] = version
				system_data[:kernel] = kernel_version
			else
				print_good("This appears to be a Debian Based System")
				version = read_file("/etc/issue").gsub(/\n|\\n|\\l/,'')
				system_data[:distro] = "debian"
				system_data[:version] = version
				system_data[:kernel] = kernel_version
			end

		elsif etc_files.include?("fedora-release")
			print_good("This appears to be a Fedora Based System")
			kernel_version = cmd_exec("uname -a")
			version = read_file("/etc/fedora-release").gsub(/\n|\\n|\\l/,'')
			system_data[:distro] = "fedora"
			system_data[:version] = version
			system_data[:kernel] = kernel_version

		elsif etc_files.include?("redhat-release")
			print_good("This appears to be a RedHat Based System")
			kernel_version = cmd_exec("uname -a")
			version = read_file("/etc/redhat-release").gsub(/\n|\\n|\\l/,'')
			system_data[:distro] = "redhat"
			system_data[:version] = version
			system_data[:kernel] = kernel_version

		elsif etc_files.include?("slackware-version")
			print_good("This appears to be a Slackware Based System")
			kernel_version = cmd_exec("uname -a")
			version = read_file("/etc/slackware-version").gsub(/\n|\\n|\\l/,'')
			system_data[:distro] = "slackware"
			system_data[:version] = version
			system_data[:kernel] = kernel_version

		elsif etc_files.include?("mandrake-release")
			print_good("This appears to be a Madrake Based System")
			kernel_version = cmd_exec("uname -a")
			version = read_file("/etc/mandrake-release").gsub(/\n|\\n|\\l/,'')
			system_data[:distro] = "mandrake"
			system_data[:version] = version
			system_data[:kernel] = kernel_version

		elsif etc_files.include?("SuSE-release")
			print_good("This appears to be a SUSE Based System")
			kernel_version = cmd_exec("uname -a")
			version = read_file("/etc/SuSE-release").gsub(/\n|\\n|\\l/,'')
			system_data[:distro] = "suse"
			system_data[:version] = version
			system_data[:kernel] = kernel_version

		elsif etc_files.include?("gentoo-release")
			print_good("This appears to be a Gentoo Based System")
			kernel_version = cmd_exec("uname -a")
			version = read_file("/etc/gentoo-release").gsub(/\n|\\n|\\l/,'')
			system_data[:distro] = "gentoo"
			system_data[:version] = version
			system_data[:kernel] = kernel_version
		else
			print_error("Could not determine the linux version")
			kernel_version = cmd_exec("uname -a")
			version = read_file("/etc/issue").gsub(/\n|\\n|\\l/,'')
			system_data[:distro] = "linux"
			system_data[:version] = version
			system_data[:kernel] = kernel_version
		end
		return system_data
	end

	def get_pakages(distro)
		packages_installed = nil
		if distro =~ /fedora|redhat|suse|mandrake/
			packages_installed = cmd_exec("rpm -qa")
		elsif distro =~ /slackware/
			packages_installed = cmd_exec("ls /var/log/packages")
		elsif distro =~ /ubuntu|debian/
			packages_installed = cmd_exec("dpkg -l")
		elsif distro =~ /gentoo/
			packages_installed = cmd_exec("equery list")
		else
			print_error("Could not determine package manager to get list of installed packages")
		end
		return packages_installed
	end
end
