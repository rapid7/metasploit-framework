# -*- coding: binary -*-

#
# Gems
#

require 'highline/system_extensions'

#
# Project
#
require 'rex/ui'

begin
  require 'windows_console_color_support'
rescue ::LoadError
end

class Rex::Ui::Text::Output::Stdio < Rex::Ui::Text::Output
  #
  # CONSTANTS
  #

  # Matches TERM environment variable values that support color
  COLOR_TERM_REGEXP = /(?:vt10[03]|xterm(?:-color)?|linux|screen|rxvt)/i

  #
  # Methods
  #

  def flush
    $stdout.flush
  end

  #
  # Prints the supplied message to standard output.
  #
  def print_raw(msg = '')
    if (Rex::Compat.is_windows and supports_color?)
      windows_console_color_support = WindowsConsoleColorSupport.new($stdout)
      windows_console_color_support.write(msg)
    else
      $stdout.print(msg)
    end

    flush

    msg
  end


  def supports_color?
    color = config[:color]

    if [false, true].include? color
      color
    # auto
    else
      if Rex::Compat.is_windows
        true
      else
        term = Rex::Compat.getenv('TERM')

        if term && !term.match(COLOR_TERM_REGEXP).nil?
          true
        else
          false
        end
      end
    end
  end

  def tty?
    $stdout.tty?
  end

  # The width of the terminal.
  #
  # @return [80] if {#tty?} is false.
  # @return [Integer] if {#tty?} is true.
  # @see HighLine::SystemExtensions.terminal_size
  def width
    if tty?
      HighLine::SystemExtensions.terminal_size[0]
    else
      super
    end
  end
end
