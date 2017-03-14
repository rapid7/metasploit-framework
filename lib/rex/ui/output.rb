# -*- coding: binary -*-
require 'rex/ui'

module Rex
module Ui

###
#
# This class acts as a generic base class for outputing data.  It
# only provides stubs for the simplest form of outputing information.
#
###
class Output

  # General output
  require 'rex/ui/output/none'

  # Text-based output
  require 'rex/ui/text/output'

  #
  # Prints an error message.
  #
  def print_error(msg='')
  end

  alias_method :print_bad, :print_error

  #
  # Prints a 'good' message.
  #
  def print_good(msg='')
  end

  #
  # Prints a status line.
  #
  def print_status(msg='')
  end

  #
  # Prints an undecorated line of information.
  #
  def print_line(msg='')
  end

  #
  # Prints a warning
  #
  def print_warning(msg='')
  end

  #
  # Prints a message with no decoration.
  #
  def print(msg='')
  end

  #
  # Flushes any buffered output.
  #
  def flush
  end

  #
  # Called to tell the output medium that we're at a prompt.
  # This is used to allow the output medium to display an extra
  # carriage return
  #
  def prompting(v = true)
    @at_prompt = v
  end

  #
  # Returns whether or not we're at a prompt currently
  #
  def prompting?
    @at_prompt
  end

end

end
end
