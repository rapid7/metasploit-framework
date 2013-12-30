# -*- coding: binary -*-
require 'msf/ui/console/command_dispatcher'

# Module-specific command dispatcher.
module Msf::Ui::Console::ModuleCommandDispatcher
  include Msf::Ui::Console::CommandDispatcher

  def commands
    super.merge(
      "pry"    => "Open a Pry session on the current module",
      "reload" => "Reload the current module from disk"
    )
  end

  def cmd_pry_help
    print_line "Usage: pry"
    print_line
    print_line "Open a pry session on the current module.  Be careful, you"
    print_line "can break things."
    print_line
  end

  def cmd_pry(*args)
    begin
      require 'pry'
    rescue LoadError
      print_error("Failed to load pry, try 'gem install pry'")
      return
    end

    driver.metasploit_instance.pry
  end

  #
  # Reloads the active module
  #
  def cmd_reload(*args)
    begin
      reload
    rescue
      log_error("Failed to reload: #{$!}")
    end
  end

  @@reload_opts =  Rex::Parser::Arguments.new(
    '-k' => [ false,  'Stop the current job before reloading.' ],
    '-h' => [ false,  'Help banner.' ])

  def cmd_reload_help
    print_line "Usage: reload [-k]"
    print_line
    print_line "Reloads the current module."
    print @@reload_opts.usage
  end

  #
  # Reload the current module, optionally stopping existing job
  #
  def reload(should_stop_job=false)
    if should_stop_job and driver.metasploit_instance.job_id
      print_status('Stopping existing job...')

      framework.jobs.stop_job(self.driver.metasploit_instance.job_id)
      driver.metasploit_instance.job_id = nil
    end

    print_status('Reloading module...')

    original_metasploit_instance = driver.metasploit_instance
    reloaded_metasploit_instance = framework.modules.reload_module(original_metasploit_instance)

    unless reloaded_metasploit_instance
      error = framework.modules.module_load_error_by_path[original_metasploit_instance.file_path]

      print_error("Failed to reload module: #{error}")

      driver.metasploit_instance = original_metasploit_instance
    else
      driver.metasploit_instance = reloaded_metasploit_instance

      driver.metasploit_instance.init_ui(driver.input, driver.output)
    end

    reloaded_metasploit_instance
  end

end
