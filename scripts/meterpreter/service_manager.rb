# Author: Carlos Perez <carlos_perez [at] darkoperator.com and Shai rod (@NightRang3r)
#-------------------------------------------------------------------------------
################## Variable Declarations ##################

@client = client
srv_name           = nil
returned_value     = nil
srv_startup        = "Auto"
srv_display_name   = ""
srv_command        = nil
srv_list           = false
srv_start          = false
srv_stop           = false
srv_create         = false
srv_info           = false
srv_change_startup = false
srv_delete         = false


@exec_opts = Rex::Parser::Arguments.new(
	"-h" => [ false , "Help menu." ],
	"-l" => [ false , "List Services"],
	"-S" => [ false , "Start Service"],
	"-K" => [ false , "Stop Service"],
	"-C" => [ false , "Create Service, service will be set to auto start"],
	"-c" => [ false , "Change Service StartUp. Default <Auto>" ],
	"-i" => [ false , "Get Service Information"],
	"-n" => [ true  , "Service Name"],
	"-s" => [ true  , "Startup Parameter for service. Specify Auto, Manual or Disabled"],
	"-d" => [ true  , "Display Name of Service"],
	"-p" => [ true  , "Service command"],
	"-D" => [ false , "Delete Service"]
	)
meter_type = client.platform

################## Function Declarations ##################

# Usage Message Function
#-------------------------------------------------------------------------------
def usage
	print_line "Meterpreter Script for managing Windows Services."
	print_line(@exec_opts.usage)
	raise Rex::Script::Completed
end

# Wrong Meterpreter Version Message Function
#-------------------------------------------------------------------------------
def wrong_meter_version(meter = meter_type)
	print_error("#{meter} version of Meterpreter is not supported with this Script!")
	raise Rex::Script::Completed
end

# Check if sufficient privileges are present for certain actions
def priv_check
	if not is_uac_enabled? or is_admin?
		return true
	else
		print_error("Insuficient Privileges")
		raise Rex::Script::Completed
	end

end

################## Main ##################
# Check for Version of Meterpreter
wrong_meter_version(meter_type) if meter_type !~ /win32|win64/i

@exec_opts.parse(args) { |opt, idx, val|
	case opt
	when "-h"
		usage
	when "-l"
		srv_list = true
	when "-n"
		srv_name = val
	when "-S"
		srv_start = true
	when "-K"
		srv_stop = true
	when "-i"
		srv_info = true
	when "-c"
		srv_change_startup = true
	when "-C"
		srv_create = true
	when "-d"
		srv_display_name = val
	when "-p"
		srv_command = val
	when "-D"
		srv_delete = true
	end
}

# List Services
if srv_list
	print_status("Service List:")
	service_list.each do |s|
		print_good("\t#{s}")
	end
	raise Rex::Script::Completed

# Start a service
elsif srv_start
	priv_check
	if srv_name
		begin
			returned_value = service_start(srv_name)
			if returned_value == 0
				print_good("Service #{srv_name} Started")
			elsif returned_value == 1
				print_good("Service #{srv_name} already Running")
			elsif returned_value == 2
				print_error("Service #{srv_name} is Disabled could not be started.")
			end

		rescue
			print_error("A Service Name must be provided, service names are case sensitive.")
		end
	else
		print_error("No Service Name was provided!")
	end
	raise Rex::Script::Completed

# Stop a Service
elsif srv_stop
	priv_check
	if srv_name
		begin
			returned_value = service_stop(srv_name)
			if returned_value == 0
				print_good("Service #{srv_name} Stopped")
			elsif returned_value == 1
				print_good("Service #{srv_name} already Stopped")
			elsif returned_value == 2
				print_error("Service #{srv_name} can not be stopped.")
			end

		rescue
			print_error("A Service Name must be provided, service names are case sensitive.")
		end
	else
		print_error("No Service Name was provided!")
	end
	raise Rex::Script::Completed

# Get service info
elsif srv_info
	srv_conf = {}
	if srv_name
		begin
			srv_conf = service_info(srv_name)
			print_status("Service Information for #{srv_name}:")
			print_good("\tName: #{srv_conf['Name']}")
			print_good("\tStartup: #{srv_conf['Startup']}")
			print_good("\tCommand: #{srv_conf['Command']}")
			print_good("\tCredentials: #{srv_conf['Credentials']}")
		rescue
			print_error("A Service Name must be provided, service names are case sensitive.")
		end
	else
		print_error("No Service Name was provided!")
	end
	raise Rex::Script::Completed

# Change startup of a service
elsif srv_change_startup
	priv_check
	if srv_name
		begin
			print_status("Changing Service #{srv_name} Startup to #{srv_startup}")
			service_change_startup(srv_name,srv_startup)
			print_good("Service Startup changed!")

		rescue
			print_error("A Service Name must be provided, service names are case sensitive.")
		end
	else
		print_error("No Service Name was provided!")
	end
	raise Rex::Script::Completed

# Create a service
elsif srv_create
	priv_check
	if srv_name and srv_command
		begin
			print_status("Creating Service #{srv_name}")
			service_create(srv_name,srv_display_name,srv_command)
			print_good("\tService Created!")
			print_good("\tDisplay Name: #{srv_display_name}")
			print_good("\tCommand: #{srv_command}")
			print_good("\tSet to Auto Star.")
		rescue::Exception => e
			print_error("Error: #{e}")
		end
	else
		print_error("No Service Name and Service Command where provided!")
	end

# Delete a service
elsif srv_delete
	priv_check
	if srv_name
		begin
			print_status("Deleting Service #{srv_name}")
			service_delete(srv_name)
			print_good("\tService #{srv_name} Delete")
		rescue::Exception => e
			print_error("A Service Name must be provided, service names are case sensitive.")
			print_error("Error: #{e}")
		end
	else
		print_error("No Service Name and Service Command where provided!")
	end
	raise Rex::Script::Completed
else
	usage
end
