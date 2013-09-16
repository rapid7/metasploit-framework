# -*- coding: binary -*-
require 'rex/ui'

begin
  require 'windows_console_color_support'
rescue ::LoadError
end

module Rex
module Ui
module Text

###
#
# This class implements output against standard out.
#
###
class Output::Stdio < Rex::Ui::Text::Output

  def supports_color?
    case config[:color]
    when true
      return true
    when false
      return false
    else # auto
      if (Rex::Compat.is_windows)
        return true
      end
      term = Rex::Compat.getenv('TERM')
      return (term and term.match(/(?:vt10[03]|xterm(?:-color)?|linux|screen|rxvt)/i) != nil)
    end
  end

  #
  # Prints the supplied message to standard output.
  #
  def print_raw(msg = '')
    if (Rex::Compat.is_windows and supports_color?)
      WindowsConsoleColorSupport.new($stdout).write(msg)
    else
      $stdout.print(msg)
    end
    $stdout.flush

    msg
  end
end

end
end
end

