# -*- coding: binary -*-
module Msf
module Session
module Provider

###
#
# Executes a single command and optionally allows for reading/writing I/O
# to the new process.
#
###
module SingleCommandExecution

  #
  # Initializes the executed command for reading/writing.
  #
  def init_cmd(command, arguments = nil, opts = nil)
  end

  #
  # Reads output from the command.
  #
  def read_cmd(length = nil)
  end

  #
  # Writes input to the command.
  #
  def write_cmd(buf)
  end

  #
  # Closes the command that was executed.
  #
  def close_cmd()
  end

end

end
end
end
