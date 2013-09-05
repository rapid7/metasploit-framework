# -*- coding: binary -*-
module Rex
module Ui

###
#
# This module provides a subscriber interface to input/output.
#
###
module Subscriber

  ##
  #
  # Subscribes to the output half of the user interface.
  #
  ##
  module Output

    #
    # Wraps user_output.print_line
    #
    def print_line(msg='')
      if (user_output)
        print_blank_line if user_output.prompting?
        user_output.print_line(msg)
      end
    end

    #
    # Wraps user_output.print_status
    #
    def print_status(msg='')
      if (user_output)
        print_blank_line if user_output.prompting?
        user_output.print_status(msg)
      end
    end

    #
    # Wraps user_output.print_error
    #
    def print_error(msg='')
      if (user_output)
        print_blank_line if user_output.prompting?
        user_output.print_error(msg)
      end
    end

    #
    # Wraps user_output.print_good
    #
    def print_good(msg='')
      if (user_output)
        print_blank_line if user_output.prompting?
        user_output.print_good(msg)
      end
    end

    #
    # Wraps user_output.print_debug
    #
    def print_debug(msg='')
      if (user_output)
        print_blank_line if user_output.prompting?
        user_output.print_debug(msg)
      end
    end

    #
    # Wraps user_output.print_warning
    #
    def print_warning(msg='')
      if (user_output)
        print_blank_line if user_output.prompting?
        user_output.print_warning(msg)
      end
    end

    #
    # Wraps user_output.print
    #
    def print(msg='')
      user_output.print(msg) if (user_output)
    end

    #
    # Wraps user_output.flush
    #
    def flush
      user_output.flush if (user_output)
    end

    #
    # The user output handle.
    #
    attr_accessor :user_output

  protected

    #
    # Prints a blank line.  Used when the input is prompting.
    #
    def print_blank_line
      user_output.prompting(false)
      user_output.print_line
    end

  end

  ##
  #
  # Subscribes to the input half of the user interface.
  #
  ##
  module Input

    #
    # Gets a line of input from the user_input handle by calling gets.
    #
    def gets
      user_input.gets if (user_input)
    end

    #
    # The user intput handle.
    #
    attr_accessor :user_input

  end

  include Output
  include Input

  #
  # Sets the input and output handles.
  #
  def init_ui(input = nil, output = nil)
    self.user_input  = input
    self.user_output = output
  end

  #
  # Disables input/output
  #
  def reset_ui
    self.user_input  = nil
    self.user_output = nil
  end

  #
  # Copy the user input and output handles from the supplied subscriber.
  #
  def copy_ui(subscriber)
    init_ui(subscriber.user_input, subscriber.user_output)
  end

end

end
end
