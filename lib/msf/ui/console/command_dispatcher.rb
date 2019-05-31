# -*- coding: binary -*-
require 'msf/ui/console/command_dispatcher/common'
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
  # Return the subdir of the `documentation/` directory that should be used
  # to find usage documentation
  #
  def docs_dir
    File.join(super, 'msfconsole')
  end

  #
  # Generate an array of job or session IDs from a given range String.
  # Always returns an Array.
  #
  # @param id_list [String] Range or list description such as 1-5 or 1,3,5 etc
  # @return [Array<String>] Representing the range
  def build_range_array(id_list)
    item_list = []
    unless id_list.blank?
      temp_list = id_list.split(/[, ]*/)
      temp_list.each do |ele|
        return if ele.count('-') > 1
        return if ele.first == '-' || ele[-1] == '-'
        return if ele.first == '.' || ele[-1] == '.'
        return unless ele =~ (/^\d+((\.\.|-)\d+)?$/)  # Not a number or range

        if ele.include? '-'
          temp_array = (ele.split("-").inject { |s, e| s.to_i..e.to_i }).to_a
          item_list.concat(temp_array)
        elsif ele.include? '..'
          temp_array = (ele.split("..").inject { |s, e| s.to_i..e.to_i }).to_a
          item_list.concat(temp_array)
        else
          item_list.push(ele.to_i)
        end
      end
    end

    item_list.uniq.sort
  end

  #
  # Remove lines with specific substring
  #
  # @param text [String] Block of text to search over
  # @param to_match [String] String that when found, causes the whole line to
  #   be removed, including trailing "\n" if present
  # @return [String] Text sans lines containing to_match
  #
  def remove_lines(text, *lines)
    out = text.dup
    lines.each do |to_match|
      to_match = Regexp.escape(to_match)
      out.gsub!(/^.*(#{to_match}).*(#{Regexp.escape $/})?/, '')
    end

    out
  end

  #
  # The driver that this command dispatcher is associated with.
  #
  attr_accessor :driver

end
end end end

require 'msf/ui/console/module_command_dispatcher'
require 'msf/ui/console/command_dispatcher/core'

