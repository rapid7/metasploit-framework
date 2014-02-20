# -*- coding: binary -*-
require 'rex/ui'

module Rex
module Ui
module Text

###
#
# This class implements input against a socket.
#
###
class Input::Socket < Rex::Ui::Text::Input

  def initialize(sock)
    @sock = sock
  end

  #
  # Sockets do not currently support readline.
  #
  def supports_readline
    false
  end

  #
  # Reads input from the raw socket.
  #
  def sysread(len = 1)
    @sock.sysread(len)
  end

  #
  # Wait for a line of input to be read from a socket.
  #
  def gets

    # Initialize the line buffer
    line = ''

    # Read data one byte at a time until we see a LF
    while (true)

      break if line.include?("\n")

      # Read another character of input
      char = @sock.getc
      if char.nil?
        @sock.close
        return
      end

      # Telnet sends 0x04 as EOF
      if (char == 4)
        @sock.write("[*] Caught ^D, closing the socket...\n")
        @sock.close
        return
      end

      # Append this character to the string
      line << char

      # Handle telnet sequences
      case line
        when /\xff\xf4\xff\xfd\x06/n
          @sock.write("[*] Caught ^C, closing the socket...\n")
          @sock.close
          return

        when /\xff\xed\xff\xfd\x06/n
          @sock.write("[*] Caught ^Z\n")
          return
      end
    end

    return line
  end

  #
  # Returns whether or not EOF has been reached on stdin.
  #
  def eof?
    @sock.closed?
  end

  #
  # Returns the file descriptor associated with a socket.
  #
  def fd
    return @sock
  end
end

end
end
end
