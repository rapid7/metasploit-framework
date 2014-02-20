# -*- coding: binary -*-
require 'rex/ui'

module Rex
module Ui
module Text

###
#
# This class implements output against a file
#
###
class Output::File < Rex::Ui::Text::Output

  attr_accessor :fd

  def initialize(path)
    self.fd = ::File.open(path, "wb")
  end

  def supports_color?
    false
  end

  #
  # Prints the supplied message to file output.
  #
  def print_raw(msg = '')
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

