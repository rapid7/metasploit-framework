module MsfTest
module MeterpreterSpecs

  def self.included(base)
        	base.class_eval do

    it "should not error when running each command" do
        commands = [ 	"?",
            "background",
            "bgkill",
            "bglist",
            "bgrun",
            "channel",
            "close",
            "exit",
            "help",
            "interact",
            #"irb",
            "migrate",
            #"quit",
            "read",
            "run",
            "use",
            "write",
            "cat",
            "cd",
            "del",
            "download",
            #"edit",
            "getlwd",
            "getwd",
            "lcd",
            "lpwd",
            "ls",
            "mkdir",
            "pwd",
            "rm",
            "rmdir",
            "search",
            "upload",
            "ipconfig",
            "portfwd",
            "route",
            "clearev",
            "drop_token",
            "execute",
            "getpid",
            "getprivs",
            "getuid",
            "kill",
            "ps",
            #"reboot",
            "reg",
            "rev2self",
            #"shell",
            #"shutdown",
            "steal_token",
            "sysinfo",
            "enumdesktops",
            "getdesktop",
            "idletime",
            "keyscan_dump",
            "keyscan_start",
            "keyscan_stop",
            "screenshot",
            "setdesktop",
            "uictl",
            "getsystem",
            "hashdump",
            "timestomp"
            ]

        ## Run each command, check for execeptions
        commands.each do |command|
          hlp_run_command_check_output("basic_#{command}",command)
        end
      end	

      it "should not error when running help" do
        success_strings = [ 	'Core Commands',
              'Stdapi: File system Commands',
              'Stdapi: Networking Commands',
              'Stdapi: System Commands',
              'Stdapi: User interface Commands']
          
        hlp_run_command_check_output("help","help", success_strings)
      end
  
      it "should not error when running the help shortcut" do
        success_strings = [ 	'Core Commands',
              'Stdapi: File system Commands',
              'Stdapi: Networking Commands',
              'Stdapi: System Commands',
              'Stdapi: User interface Commands' ]
          
        hlp_run_command_check_output("help_shortcut","?", success_strings)
      end	
    
      it "should not error when checking for background channels" do
        success_strings = [ 'No active channels.' ]
        hlp_run_command_check_output("channel_list_empty","channel -l", success_strings)
      end
  
    end
  end

end
end
