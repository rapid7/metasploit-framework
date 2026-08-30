# -*- coding: binary -*-
module Msf
module Session
module Provider

###
#
# Executes multiple commands and optionally allows for reading/writing I/O
# to the new processes.
#
###
module MultiCommandExecution

  #
  # Initializes the single command instance that will be used
  # implicitly if no command is supplied to any of the functions.
  #
  def init_cmd(command, arguments = nil, opts = nil)
  end

  #
  # Executes a command with the supplied options, returning a context
  # that should be supplied to future calls.  Supported options:
  #
  #   - Hidden
  #     Launch the command hidden from view.
  #
  def exec_cmd(command, arguments = nil, opts = nil)
  end

  #
  # Reads output from a command.  If no command is supplied, the default
  # command is used.
  #
  def read_cmd(length = nil, cmd = nil)
  end

  #
  # Writes input to a command.  If no command is supplied, the default
  # command is used.
  #
  def write_cmd(buf, cmd = nil)
  end

  #
  # Closes a command that was executed.  If no command is supplied, the
  # default command is used.
  #
  def close_cmd(cmd = nil)
  end

end

end
end
end
