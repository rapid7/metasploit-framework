# -*- coding: binary -*-
require 'rex/ui'

module Rex
module Ui
module Text

###
#
# This class implements output against a file and stdout
#
###
class Output::Tee < Rex::Ui::Text::Output

  attr_accessor :fd

  def initialize(path)
    self.fd = ::File.open(path, "ab")
    super()
  end

  def supports_color?
    case config[:color]
    when true
      return true
    when false
      return false
    else # auto
      term = Rex::Compat.getenv('TERM')
      return (term and term.match(/(?:vt10[03]|xterm(?:-color)?|linux|screen|rxvt)/i) != nil)
    end
  end

  #
  # Prints the supplied message to file output.
  #
  def print_raw(msg = '')
    $stdout.print(msg)
    $stdout.flush

    return if not self.fd
    self.fd.write(msg)
    self.fd.flush
    msg
  end

  def close
    self.fd.close if self.fd
    self.fd = nil
  end
end

end
end
end

