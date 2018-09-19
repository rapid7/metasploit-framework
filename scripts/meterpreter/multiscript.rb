##
# WARNING: Metasploit no longer maintains or accepts meterpreter scripts.
# If you'd like to improve this script, please try to port it as a post
# module instead. Thank you.
##



#Meterpreter script for running multiple scripts on a Meterpreter Session
#Provided by Carlos Perez at carlos_perez[at]darkoperator[dot]com
#Verion: 0.2
################## Variable Declarations ##################
session = client
# Setting Argument

@@exec_opts = Rex::Parser::Arguments.new(
  "-h" => [ false,"Help menu."                        ],
  "-c" => [ true,"Collection of scripts to execute. Each script command must be enclosed in double quotes and separated by a semicolon."],
  "-r" => [ true,"Text file with list of commands, one per line."]
)
#Setting Argument variables
commands = ""
script = []
help = 0

################## Function Declarations ##################
# Function for running a list of scripts stored in a array
def script_exec(session,scrptlst)
  print_status("Running script List ...")
  scrptlst.each_line do |scrpt|
    next if scrpt.strip.length < 1
    next if scrpt[0,1] == "#"

    begin
      script_components = scrpt.split
      script = script_components.shift
      script_args = script_components
      print_status "\trunning script #{scrpt.chomp}"
      session.execute_script(script, script_args)
    rescue ::Exception => e
      print_error("Error: #{e.class} #{e}")
      print_error("Error in script: #{scrpt}")
    end
  end
end

def usage
  print_line("Multi Script Execution Meterpreter Script ")
  print_line(@@exec_opts.usage)
end

################## Main ##################
@@exec_opts.parse(args) do |opt, idx, val|
  case opt

  when "-c"
    commands = val.gsub(/;/,"\n")
  when "-r"
    script = val
    if not ::File.exist?(script)
      raise "Script List File does not exists!"
    else
      ::File.open(script, "rb").each_line do |line|
        commands << line
      end
    end
  when "-h"
    help = 1
  end
end


if args.length == 0 or help == 1
  usage
else
  print_status("Running Multiscript script.....")
  script_exec(session,commands)
end
