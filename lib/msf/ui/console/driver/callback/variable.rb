module Msf::Ui::Console::Driver::Callback::Variable
  #
  # Called when a variable is set to a specific value.  This allows the
  # console to do extra processing, such as enabling logging or doing
  # some other kind of task.  If this routine returns false it will indicate
  # that the variable is not being set to a valid value.
  #
  def on_variable_set(glob, var, val)
    case var.downcase
      when "payload"

        if (framework and framework.payloads.valid?(val) == false)
          return false
        elsif (metasploit_instance)
          metasploit_instance.datastore.clear_non_user_defined
        elsif (framework)
          framework.datastore.clear_non_user_defined
        end
      when "sessionlogging"
        handle_session_logging(val) if (glob)
      when "consolelogging"
        handle_console_logging(val) if (glob)
      when "loglevel"
        handle_loglevel(val) if (glob)
      when "prompt"
        update_prompt(val, prompt_char, true)
      when "promptchar"
        update_prompt(framework.datastore['Prompt'], val, true)
    end
  end

  #
  # Called when a variable is unset.  If this routine returns false it is an
  # indication that the variable should not be allowed to be unset.
  #
  def on_variable_unset(glob, var)
    case var.downcase
      when "sessionlogging"
        handle_session_logging('0') if (glob)
      when "consolelogging"
        handle_console_logging('0') if (glob)
      when "loglevel"
        handle_loglevel(nil) if (glob)
    end
  end

  private

  #
  # ConsoleLogging.
  #
  def handle_console_logging(val)
    if (val =~ /^(y|t|1)/i)
      Msf::Logging.enable_log_source('console')
      print_line("Console logging is now enabled.")

      set_log_source('console')

      rlog("\n[*] Console logging started: #{Time.now}\n\n", 'console')
    else
      rlog("\n[*] Console logging stopped: #{Time.now}\n\n", 'console')

      unset_log_source

      Msf::Logging.disable_log_source('console')
      print_line("Console logging is now disabled.")
    end
  end

  #
  # This method handles adjusting the global log level threshold.
  #
  def handle_loglevel(val)
    set_log_level(Rex::LogSource, val)
    set_log_level(Msf::LogSource, val)
  end

  #
  # SessionLogging.
  #
  def handle_session_logging(val)
    if (val =~ /^(y|t|1)/i)
      Msf::Logging.enable_session_logging(true)
      print_line("Session logging will be enabled for future sessions.")
    else
      Msf::Logging.enable_session_logging(false)
      print_line("Session logging will be disabled for future sessions.")
    end
  end
end