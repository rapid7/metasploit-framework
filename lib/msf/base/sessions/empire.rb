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

  attr_accessor :max_threads
  attr_accessor :platform
  attr_accessor :arch

  def desc
    "Empire Shell #{self.platform}"
  end

  def self.type
    "Empire"
  end

  def name (session_name)
    self.sname = session_name
  end

  def initialize(emp_object, agent_name)
    self.plaform ||= ""
    self.max_threads ||= 1
    self.arch ||= ""

    #Defining instance parameters
    self.client_emp = emp_object
    self.agent_name = agent_name
  end



  #list of available commands
  def commands
    {
      'help'        => 'Show help menu',
      'show_modules'=> 'List all the Empire post modules available to deploy against the target',
      'show_info'   => 'Displays all the available options and description of the specified module',
      'use_module'  => 'Attemps to run the specified module against the current agent',
      'shell'       => 'Run shell commands on target system'
    }
  end

  #
  #Define available commands
  #Defining help command
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

  #Defining show_modules command
  def cmd_show_modules
    self.client_emp.get_modules
  end

  #Defining show_info_help
  def show_info_help
    print_line "Usage : show_info <module_name>"
    print_line "Example : show_info powershell/situational_awareness/network/powerview/find_gpo_location"
    print_line
    print_line "Displays all the available options and description of the specified modules"
    print_line
  end

  #Define use_module_help
  def use_module_help
    print_line "Usage : use_info <module_name>"
    print_line "Example : use_module powershell/situational_awareness/networ/powerview/find_gpo_location"
    print_line
    print_line "Attempts to run the specified module against the current agent"
    print_line
  end

  #Defining show_info command
  def cmd_show_info(*args)
    if args.length.zero? || args[0] == '-h' or args[0] == 'help'
      return show_info_help
    else
      module_name = args[0]
      self.client_emp.info_module(module_name)
    end
  end

  #Defining use_module command
  def cmd_use_module(*args)
    if args.length.zero? || args[0] == '-h' or args[0] == 'help'
      return use_module_help
    else
      module_name = args[0]
      self.client_emp.exec_module(module_name, self.agent_name)
    end
  end

  #Defining shell command
  def cmd_shell
    shell_command = ''
    while shell_command != 'exit'
      print "empire-shell > "
      shell_command = gets
      response = self.client_emp(self.agent_name,command)
      if response.to_s.include?("successfully")
        sleep(5)
        puts self.client_emp.get_results(self.agent_name)
        self.client_emp.delete_results(self.agent_name)
      else
        print_error "#{response}"
      end
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
