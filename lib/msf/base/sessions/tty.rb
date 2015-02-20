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
class TTY

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
    "tty"
  end

  #
  # Returns the session description.
  #
  def desc
    "Interactive TTY"
  end

  def run_cmd(cmd)
    shell_write(cmd)
    return rstream.get
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
    if length.nil?
      rv = rstream.get
    else
      rv = rstream.read(length)
    end
    return rv
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

end

end
end
