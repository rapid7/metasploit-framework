##
# WARNING: Metasploit no longer maintains or accepts meterpreter scripts.
# If you'd like to improve this script, please try to port it as a post
# module instead. Thank you.
##


#
# Meterpreter script for running multiple console commands on a meterpreter session
# Provided by Carlos Perez at carlos_perez[at]darkoperator[dot]com
# Verion: 0.1
#

################## Variable Declarations ##################
@client = client

# Setting Arguments
@@exec_opts = Rex::Parser::Arguments.new(
  "-h" => [ false,"Help menu."                        ],
  "-s" => [ false,"Hide commands output for work in background sessions"],
  "-c" => [ true,"Commands to execute. The command must be enclosed in double quotes and separated by a comma."],
  "-r" => [ true,"Text file with list of commands, one per line."]
)

commands = nil
script = []
help = false
silence = false

def usage
  print_line("Console Multi Command Execution Meterpreter Script ")
  print_line(@@exec_opts.usage)
  raise Rex::Script::Completed
end

@@exec_opts.parse(args) { |opt, idx, val|
  case opt

  when "-c"
    commands = val.split(",")
  when "-r"
    script = val
    if not ::File.exist?(script)
      raise "Command List File does not exists!"
    else
      commands = []
      ::File.open(script, "r").each_line do |line|
        commands << line.chomp
      end
    end

  when "-h"
    help = true
  when "-s"
    silence = true
  end
}

if args.length == 0 or help or commands.nil?
  usage
end

print_status("Running Command List ...")

commands.each do |cmd|
  next if cmd.strip.length < 1
  next if cmd[0,1] == "#"
  begin
    print_status "\tRunning command #{cmd}"
    if silence
        @client.console.disable_output = true
    end

    @client.console.run_single(cmd)

    if silence
      @client.console.disable_output = false
    end

  rescue ::Exception => e
    print_status("Error Running Command #{cmd}: #{e.class} #{e}")
  end
end
