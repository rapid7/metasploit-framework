# -*- coding: binary -*-
require 'rex/sync/ref'

module Msf

###
#
# This module represents an abstract plugin that can be loaded into the
# context of a framework instance.  Plugins are meant to provide an easy way
# to augment the feature set of the framework by being able to load and unload
# them during the course of a framework's lifetime.  For instance, a plugin
# could be loaded to alter the default behavior of new sessions, such as by
# scripting meterpreter sessions that are created.  The possiblities are
# endless!
#
# All plugins must exist under the Msf::Plugin namespace.  Plugins are
# reference counted to allow them to be loaded more than once if they're a
# singleton.
#
###
class Plugin

  include Framework::Offspring
  include Rex::Ref

  #
  # Create an instance of the plugin using the supplied framework instance.
  # We use create instead of new directly so that singleton plugins can just
  # return their singleton instance.
  #
  def self.create(framework, opts = {})
    new(framework, opts)
  end

  #
  # Initializes the plugin instance with the supplied framework instance.
  # The opts parameter is a hash of custom arguments that may be useful for a
  # plugin.  Some of the pre-defined arguments are:
  #
  # LocalInput
  #
  # 	The local input handle that implements the Rex::Ui::Text::Input
  # 	interface.
  #
  # LocalOutput
  #
  # 	The local output handle that implements the Rex::Ui::Output interface.
  #
  def initialize(framework, opts = {})
    self.framework  = framework
    self.opts       = opts

    refinit
  end

  #
  # Allows the plugin to clean up as it is being unloaded.
  #
  def cleanup
  end

  ##
  #
  # Accessors
  #
  ##

  #
  # Returns the name of the plugin.
  #
  def name
    "unnamed"
  end

  #
  # A short description of the plugin.
  #
  def desc
  end

  ##
  #
  # Accessors
  #
  ##

  #
  # Returns the local output handle if one was passed into the constructor.
  #
  def output
    opts['LocalOutput']
  end

  #
  # Returns the local input handle if one was passed into the constructor.
  #
  def input
    opts['LocalInput']
  end

  ##
  #
  # Output wrappers for the plugin that uses the 'LocalOutput' hash entry
  # if one was passed into the constructor.
  #
  ##

  #
  # Prints an error message.
  #
  def print_error(msg='')
    output.print_error(msg) if (output)
  end

  #
  # Prints a 'good' message.
  #
  def print_good(msg='')
    output.print_good(msg) if (output)
  end

  #
  # Prints a 'debug' message.
  #
  def print_debug(msg='')
    output.print_debug(msg) if (output)
  end

  #
  # Prints a status line.
  #
  def print_status(msg='')
    output.print_status(msg) if (output)
  end

  #
  # Prints an undecorated line of information.
  #
  def print_line(msg='')
    output.print_line(msg) if (output)
  end

  #
  # Prints a warning
  #
  def print_warning(msg='')
    output.print_warning(msg) if (output)
  end


  #
  # Prints a message with no decoration.
  #
  def print(msg='')
    output.print(msg) if (output)
  end

  #
  # Flushes any buffered output.
  #
  def flush
    output.flush(msg) if (output)
  end

protected

  attr_accessor :opts # :nodoc:

  ##
  #
  # Console command dispatcher helpers.
  #
  ##

  #
  # Adds the console dispatcher.
  #
  def add_console_dispatcher(disp)
    if (opts['ConsoleDriver'])
      opts['ConsoleDriver'].append_dispatcher(disp)
    end
  end

  #
  # Removes the console dispatcher.
  #
  def remove_console_dispatcher(name)
    if (opts['ConsoleDriver'])
      opts['ConsoleDriver'].remove_dispatcher(name)
    end
  end

end

end
