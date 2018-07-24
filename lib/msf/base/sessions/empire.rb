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
      'search'      => 'Fetch all the modules resembling to your search term',
      'show_info'   => 'Displays all the available options and description of the specified module',
      'use_module'  => 'Attemps to run the specified module against the current agent',
      'shell'       => 'Run shell commands on target system',
      'result'      => 'Fetch stored results from the Empire Database',
      'credentials' => 'Fetch all the saved credentials in the Empire Database',
      'rename_agent'=> 'Rename the curret agent name for easier interaction'
    }
  end

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

  #Defining a help method to display command helps.
  def get_help(usage, example, desc)
    print_line "Usage : #{usage}"
    print_line "Example : #{example}"
    print_line
    print_line "#{desc}"
    print_line
  end
  #
  #COMMAND METHODS
  #----------------------
  #
  #Defining show_info command
  def cmd_show_info(*args)
    if args.length.zero? || args[0] == '-h' or args[0] == 'help'
      return get_help("show_info <module_name>","show_info powershell/situational_awareness/network/powerview/find_gpo_location","Displays all the available options and description of the specified modules")
    else
      module_name = args[0]
      @client_emp.info_module(module_name)
    end
  end

  #Defining use_module command
  def cmd_use_module(*args)
    if args.length.zero? || args[0] == '-h' or args[0] == 'help'
      return get_help("use_module <module_name>","use_module powershell/situational_awareness/network/powerview/find_gpo_location","Attempts to run the specified module against the current agent")
    else
      module_name = args[0]
      @client_emp.exec_module(module_name, @agent_name)
    end
  end

  #Defining search command
  def cmd_search(*args)
    if args.length.zero? || args[0] == '-h' or args[0] == 'help'
      return get_help("search <key_term>","search privesc","Fetch all the modules resembling to your key term")
    else
      keyterm = args[0].to_s
      @client_emp.search_module(keyterm)
    end
  end

  #Defining show_modules command
  def cmd_show_modules
    @client_emp.get_modules
  end

  #Defining empire shell command
  def cmd_shell(*args)
    if args.length = 1
      command = args[0]
      puts @client_emp.exec_command(@agent_name, command)
    elsif args.length > 1
      command = args.join(" ")
      puts @client_emp.exec_command(@agent_name, command)
    elsif args.length.zero? || args[0] == '-h' or args[0] == 'help'
      return get_help("shell <shell_command>","shell start notepad.exe","Runs a shell command in target host and stores the result in Empire Database. Please wait few moments before fetching the results, for results to be properly populated")
    end
  end

  #Defining results command
  def results(*args)
    if args.length.zero? || args[0] == '-h' or args[0] == 'help'
      return get_help("results <taskID_of_the_action>","results 9","Fetch the respective results of a task from the Empire Database")
    else
      taskID = args[0]
      puts @client_emp.get_results(@agent_name, taskID)
    end
  end

  #Defining the credentials command
  def credentials
    @client_emp.get_creds
  end

  #Defining rename_agent command
  def cmd_rename_agent(*args)
    if args.length.zero? || args[0] == '-h' or args[0] == 'help'
      return get_help("rename <new_name>","rename target_1","Renames the current aget for easier future reference")
    else
      new_name = args[0].to_s
      @client_emp.rename_agent(@agent_name,new_name)
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
