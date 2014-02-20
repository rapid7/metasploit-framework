# -*- coding: binary -*-
require 'msf/base'

module Msf
module Sessions

###
#
# This class provides basic interaction with a command shell on the remote
# endpoint.  This session is initialized with a stream that will be used
# as the pipe for reading and writing the command shell.
#
###
class NetwareConsole

  #
  # This interface supports basic interaction.
  #
  include Msf::Session::Basic

  #
  # This interface supports interacting with a single command shell.
  #
  include Msf::Session::Provider::SingleCommandShell

  #
  # Returns the type of session.
  #
  def self.type
    "shell"
  end

  #
  # Returns the session description.
  #
  def desc
    "NetWare Console"
  end

  #
  # Calls the class method.
  #
  def type
    self.class.type
  end

  #
  # The shell will have been initialized by default.
  #
  def shell_init
    return true
  end

  #
  # Read from the command shell.
  #
  def shell_read(length = nil)
    return rstream.read(length)
  end

  #
  # Writes to the command shell.
  #
  def shell_write(buf)
    rstream.write(buf)
  end

  #
  # Closes the shell.
  #
  def shell_close()
    rstream.close
  end

  def _stream_read_remote_write_local(stream)
    buf = stream.get
    bsize = 25 * 80 +8

    while buf.length > 0
      data = buf[0, bsize]

      user_output.print("\e[24A")

      for i in 0..24
        user_output.print(data[8+i*80, 80] + "\n")
      end

      col = data[4, 2].unpack('v')[0]
      line = 25-data[6, 2].unpack('v')[0]
      user_output.print("\e[#{line}A")
      user_output.print("\e[#{col}C")

      if (buf.length == bsize)
        buf = ''
      else
        buf = buf[bsize, buf.length]
      end
    end
  end

end

end
end
