#Meterpreter script for running multiple scripts on a Meterpreter Session
#Provided by Carlos Perez at carlos_perez[at]darkoperator[dot]com
#Verion: 0.1
################## Variable Declarations ##################
session = client
# Setting Arguments
@@exec_opts = Rex::Parser::Arguments.new(
        "-h" => [ false,"Help menu."                        ],
        "-c" => [ true,"Collection of scripts to execute. Each script command must be enclosed in double quotes and separated by a semicolon."],
        "-s" => [ true,"Text file with list of commands, one per line."]
)
#Setting Argument variables
commands = []
script = []
help = 0

################## Function Declarations ##################
# Function for running a list of scripts stored in a array
def script_exec(session,scrptlst)
	print_status("Running script List ...")
	scrptlst.each do |scrpt|
		begin
			print_status "\trunning command #{scrpt}"

                        # Set up some local bindings.
                        input  = shell.input
                        output = shell.output

                        args = scrpt.split
                        session.execute_script(args.shift, binding)
                rescue ::Exception => e
                        print_error("Error: #{e.class} #{e}")
                        print_error("Error in script: #{scrpt}")
                end
        end
end

def usage
print_line("Multi Script Execution Meterpreter Script ")
puts @@exec_opts.usage
end
################## Main ##################
@@exec_opts.parse(args) { |opt, idx, val|
case opt

when "-c"
        commands = val.split(";")
when "-s"
        script = val
        if not ::File.exists?(script)
                raise "Script List File does not exists!"
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
        print_status("Running Multiscript script.....")
        script_exec(session,commands)
end
