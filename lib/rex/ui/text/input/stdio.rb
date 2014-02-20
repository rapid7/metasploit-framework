# -*- coding: binary -*-
require 'rex/ui'

module Rex
module Ui
module Text

###
#
# This class implements input against standard in.
#
###
class Input::Stdio < Rex::Ui::Text::Input

  #
  # Reads text from standard input.
  #
  def sysread(len = 1)
    $stdin.sysread(len)
  end

  #
  # Wait for a line of input to be read from standard input.
  #
  def gets
    return $stdin.gets
  end

  #
  # Returns whether or not EOF has been reached on stdin.
  #
  def eof?
    $stdin.closed?
  end

  #
  # Returns the file descriptor associated with standard input.
  #
  def fd
    return $stdin
  end
end

end
end
end
