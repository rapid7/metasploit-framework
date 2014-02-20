# -*- coding: binary -*-
require 'rex/ui'

module Rex
module Ui
module Text

###
#
# This class implements output against a buffer.
#
###
class Output::Buffer < Rex::Ui::Text::Output

  #
  # Initializes an output buffer.
  #
  def initialize
    self.buf = ''
  end

  def supports_color?
    false
  end

  #
  # Appends the supplied message to the output buffer.
  #
  def print_raw(msg = '')
    self.buf += msg || ''

    msg
  end


  #
  # Read everything out of the buffer and reset it
  #
  def dump_buffer
    self.buf ||= ''
    buffer = self.buf.dup
    reset()
    buffer
  end

  #
  # Reset the buffer to an empty string.
  #
  def reset
    self.buf = ''
  end

  #
  # The underlying buffer state.
  #
  attr_accessor :buf

end

end
end
end
