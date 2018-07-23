# -*- coding: binary -*-
require 'msf/ui/console/command_dispatcher.rb'
require 'msf/base/sessions/command_shell'
require 'rex/ui/text/table.rb'
require 'msf/base'

module Msf
module Sessions

class EmpireShell < Msf::Sessions::CommandShell
  include Msf::Session::Basic
  include Rex::Ui::Text::DispatcherShell::CommandDispatcher

  @client_emp = ''
  @agent_name = ''

  attr_accessor :max_threads
  attr_accessor :platform
  attr_accessor :arch

  def desc
    "Empire Shell #{self.platform}"
  end

  def interactive?
    true
  end

  def self.type
    "Empire"
  end

  def name (session_name)
    self.sname = session_name
  end

  def initialize(emp_object, agent_name)
    self.platform ||= ""
    self.max_threads ||= 1
    self.arch ||= ""

    #Defining instance parameters
    @client_emp = emp_object
    @agent_name = agent_name
  end



  #list of available commands
  def commands
    {
      'help'        => 'Show help menu',
      'show_modules'=> 'List all the Empire post modules available to deploy against the target',
      'show_info'   => 'Displays all the available options and description of the specified module',
      'use_module'  => 'Attemps to run the specified module against the current agent',
      'shell'       => 'Run shell commands on target system',
      'result'      => 'Fetch stored results from the Empire Database',
      'credentials' => 'Fetch all the saved credentials in the Empire Database',
      'rename_agent'=> 'Rename the curret agent name for easier interaction'
    }
  end

  #
  #Define available commands
  #Defining help command
  #
  #
  #HELP METHODS
  #------------------
  #
  def cmd_help
    help_table = Rex::Text::Table.new(
      'Header'        => 'Empire Shell Commands',
      'HeaderIndent'  => 4,
      'Prefix'        => '\n',
      'Postfix'       => '\n',
      'Coloumns'      => ['Commands','Descriptions'],
      'Indent'        => 6,
      'SortIndex'     => -1
    )
    commands.each do |command, description|
      help_table << [command, description]
    end
    print(help_table.to_s)
  end

  #Defining show_info_help
  def show_info_help
    print_line "Usage : show_info <module_name>"
    print_line "Example : show_info powershell/situational_awareness/network/powerview/find_gpo_location"
    print_line
    print_line "Displays all the available options and description of the specified modules"
    print_line
  end

  #Define use_module_heLP
  def use_module_help
    print_line "Usage : use_info <module_name>"
    print_line "Example : use_module powershell/situational_awareness/networ/powerview/find_gpo_location"
    print_line
    print_line "Attempts to run the specified module against the current agent"
    print_line
  end

  #Define rename_agent_help
  def rename_agent_help
    print_line "Usage: rename_agent <new_name>"
    print_line "Example: rename_agent target_1"
    print_line
    print_line "Renames the agent for easier interaction"
    print_line
  end

  #Defining shell_help method
  def shell_help
    print_line "Usage : shell <shell_command>"
    print_line "Example : shell start notepad.exe"
    print_line
    print_line "Runs a shell command in target host and stores the result in database. Please wait few moments before fetching the results, for the results to be populated"
    print_line
  end

  #Defining results_help
  def results_help
    print_line "Usage : results <taskID_of_the_action>"
    print_line "Example : results 9"
    print_line
    print_line "Fetch the respective results of a task from the Empire Database"
    print_line
  end
  #
  #COMMAND METHODS
  #----------------------
  #
  #Defining show_info command
  def cmd_show_info(*args)
    if args.length.zero? || args[0] == '-h' or args[0] == 'help'
      return show_info_help()
    else
      module_name = args[0]
      self.client_emp.info_module(module_name)
    end
  end

  #Defining use_module command
  def cmd_use_module(*args)
    if args.length.zero? || args[0] == '-h' or args[0] == 'help'
      return use_module_help()
    else
      module_name = args[0]
      self.client_emp.exec_module(module_name, self.agent_name)
    end
  end

  #Defining show_modules command
  def cmd_show_modules
    self.client_emp.get_modules
  end

  #Defining empire shell command
  def cmd_shell(*args)
    if args.length = 1
      command = args[0]
      puts self.client_emp.exec_command(self.agent_name, command)
    elsif args.length > 1
      command = args.join(" ")
      puts self.client_emp.exec_command(self.agent_name, command)
    elsif args.length.zero? || args[0] == '-h' or args[0] == 'help'
      return shell_help()
    end
  end

  #Defining results command
  def results(*args)
    if args.length.zero? || args[0] == '-h' or args[0] == 'help'
      return results_help()
    else
      taskID = args[0]
      puts self.client_emp.get_results(self.agent_name, taskID)
    end
  end

  #Defining the credentials command
  def credentials
    self.client_emp.get_creds
  end

  #Defining rename_agent command
  def cmd_rename_agent(*args)
    if args.length.zero? || args[0] == '-h' or args[0] == 'help'
      return rename_agent_help
    else
      new_name = args[0].to_s
      self.client_emp(self.agent_name,new_name)
      name(new_name)
    end
  end
end

class EmpireShellWindows < EmpireShell
  def initialize(emp_object, agent_name)
    self.platform = "Windows"
    name(agent_name)
    super
  end
end

class EmpireShellLinux < EmpireShell
  def initialize(emp_object, agent_name)
    self.platform = "Linux"
    name(agent_name)
    super
  end
end

class EmpireShellOsx < EmpireShell
  def initialize(emp_object, agent_name)
    self.platform = "OSX"
    name(agent_name)
    super
  end
end
end
end
