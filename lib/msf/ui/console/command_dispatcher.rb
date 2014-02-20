# -*- coding: binary -*-

module Msf
module Ui
module Console

###
#
# The common command dispatcher base class that is shared for component-specific
# command dispatching.
#
###
module CommandDispatcher

  include Rex::Ui::Text::DispatcherShell::CommandDispatcher

  #
  # Initializes a command dispatcher instance.
  #
  def initialize(driver)
    super

    self.driver = driver
    self.driver.on_command_proc = Proc.new { |command| framework.events.on_ui_command(command) }
  end

  #
  # Returns the framework instance associated with this command dispatcher.
  #
  def framework
    return driver.framework
  end

  #
  # Returns the active module if one has been selected, otherwise nil is
  # returned.
  #
  def active_module
    driver.active_module
  end

  #
  # Sets the active module for this driver instance.
  #
  def active_module=(mod)
    driver.active_module = mod
  end

  #
  # Returns the active session if one has been selected, otherwise nil is
  # returned.
  #
  def active_session
    driver.active_session
  end

  #
  # Sets the active session for this driver instance.
  #
  def active_session=(mod)
    driver.active_session = mod
  end
  #
  # Checks to see if the driver is defanged.
  #
  def defanged?
    driver.defanged?
  end

  #
  # Logs an error message to the screen and the log file.  The callstack is
  # also printed.
  #
  def log_error(err)
    print_error(err)

    wlog(err)

    # If it's a syntax error, log the call stack that it originated from.
    dlog("Call stack:\n#{$@.join("\n")}", 'core', LEV_1)
  end

  #
  # The driver that this command dispatcher is associated with.
  #
  attr_accessor :driver

end
end end end

require 'msf/ui/console/module_command_dispatcher'
require 'msf/ui/console/command_dispatcher/core'

