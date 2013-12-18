# -*- coding: binary -*-

# The common command dispatcher base class that is shared for component-specific command dispatching.
module Msf::Ui::Console::CommandDispatcher
  include Rex::Ui::Text::DispatcherShell::CommandDispatcher

  #
  # Attributes
  #

  # @!attribute [rw] driver
  #   The driver for the UI.
  #
  #   @return [Msf::Ui::Driver]
  attr_reader :driver

  #
  # Methods
  #

  # @!method active_module
  #   The current metasploit instance.
  #
  #   @return [Msf::Module]
  #
  # @!method active_module=
  #   Sets the current metasploit instance.
  #
  #   @param metasploit_instance [Msf::Module]
  #   @return [void]
  #
  # @!method active_session
  #   The currently active session.
  #
  #   @return [nil] if no session has been selected
  #   @return [Object] if a session has been selected
  #
  # @!method active_session=
  #   Sets the currently active session.
  #
  #   @param session [Object] session to make active.
  #   @return [void]
  #
  # @!method fanged!
  #   (see Msf::Ui::Console::Driver::Fangs#fanged!)
  #
  # @!method framework
  #   The framework for which this dispatcher is running commands.
  #
  #   @return [Msf::Simple::Framework]
  delegate :active_module,
           :active_module=,
           :active_session,
           :active_session=,
           :fanged!,
           :framework,
           to: :driver

  # Set the `driver` for which this dispatcher should dispatcher commands.  Additionally registers `driver.framework` to
  # receive `ui_command` events when the `driver` processes a command.
  #
  # @return [void]
  def driver=(driver)
    @driver = driver

    driver.on_command_proc = ->(command){
      framework.events.on_ui_command(command)
    }
  end

  def initialize(driver)
    super

    self.driver = driver
    self.driver.on_command_proc = Proc.new { |command| framework.events.on_ui_command(command) }
  end

  # Logs an error message to the screen and the log file.  The callstack is
  # also printed.
  #
  # @param error [#to_s] an error
  # @return [void]
  def log_error(error)
    print_error(error)

    wlog(error)

    # If it's a syntax error, log the call stack that it originated from.
    dlog("Call stack:\n#{$@.join("\n")}", 'core', LEV_1)
  end
end

require 'msf/ui/console/module_command_dispatcher'
require 'msf/ui/console/command_dispatcher/core'

