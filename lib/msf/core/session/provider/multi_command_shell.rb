# -*- coding: binary -*-
module Msf
module Session
module Provider

###
#
# This interface is to be implemented by a session that is capable of
# providing multiple command shell interfaces simultaneously.  Inherently,
# MultiCommandShell classes must also provide a mechanism by which they can
# implement the SingleCommandShell interface.
#
###
module MultiCommandShell

  include SingleCommandShell

  #
  # Initializes the default command shell as expected from
  # SingleCommandShell.
  #
  def shell_init()
    raise NotImplementedError
  end

  #
  # Opens a new command shell context and returns the handle.
  #
  def shell_open()
    raise NotImplementedError
  end

  #
  # Reads data from a command shell.  If shell is nil, the default
  # command shell from shell_init is used.
  #
  def shell_read(length = nil, shell = nil)
    raise NotImplementedError
  end

  #
  # Writes data to a command shell.  If shell is nil, the default
  # command shell from shell_init is used.
  #
  def shell_write(buf, shell = nil)
    raise NotImplementedError
  end

  #
  # Closes the provided command shell or the default one if none is
  # given.
  #
  def shell_close(shell = nil)
    raise NotImplementedError
  end

end

end
end
end
