# -*- coding: binary -*-
require 'rex/ui'

module Rex
module Ui
module Text

###
#
# This class implements the output interface against a socket.
#
###
class Output::Socket < Rex::Ui::Text::Output

  def initialize(sock)
    @sock = sock
    super()
  end

  def supports_color?
    case config[:color]
    when true
      # Allow color if the user forces it on
      return true
    else
      false
    end
  end

  #
  # Prints the supplied message to the socket.
  #
  def print_raw(msg = '')
    @sock.write(msg)
    @sock.flush

    msg
  end
end

end
end
end

