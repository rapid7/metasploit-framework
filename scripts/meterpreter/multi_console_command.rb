# $Id:$
#Meterpreter script for running multiple console commands on a meterpreter session
#Provided by Carlos Perez at carlos_perez[at]darkoperator[dot]com
#Verion: 0.1
################## Variable Declarations ##################
session = client
# Setting Arguments
@@exec_opts = Rex::Parser::Arguments.new(
        "-h" => [ false,"Help menu."                        ],
        "-c" => [ true,"Commands to execute. The command must be enclosed in double quotes and separated by a comma."],
        "-s" => [ true,"Text file with list of commands, one per line."]
)
#Setting Argument variables
commands = []
script = []
help = 0

################## Function Declarations ##################
# Function for running a list of commands stored in a array, returs string
def list_con_exec(session,cmdlst)
	print_status("Running Command List ...")
	cmdout = ""
	cmdlst.each do |cmd|
		begin
			print_status "\tRunning command #{cmd}"
			session.console.run_single(cmd)
		rescue ::Exception => e
			print_status("Error Running Command #{cmd}: #{e.class} #{e}")
		end
	end
	cmdout
end


def usage
	print_line("Console Multi Command Execution Meterpreter Script ")
	print_line(@@exec_opts.usage)
	raise Rex::Script::Completed
end
################## Main ##################
@@exec_opts.parse(args) { |opt, idx, val|
        case opt

        when "-c"
                commands = val.split(",")
        when "-s"
                script = val
                if not ::File.exists?(script)
                        raise "Command List File does not exists!"
                else
                        ::File.open(script, "r").each_line do |line|
                                commands << line.chomp
                        end
                end

        when "-h"
                help = 1
        end

}

if args.length == 0 or help == 1 
	usage
else
	 list_con_exec(session,commands)
	 raise Rex::Script::Completed
end
