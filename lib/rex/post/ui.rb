# -*- coding: binary -*-

module Rex
module Post

###
#
# This class provides generalized user interface manipulation routines that
# might be supported by post-exploitation clients.
#
###
class UI

  #
  # This method disables the keyboard on the remote machine.
  #
  def disable_keyboard
    raise NotImplementedError
  end

  #
  # This method enables the keyboard on the remote machine.
  #
  def enable_keyboard
    raise NotImplementedError
  end

  #
  # This method disables the mouse on the remote machine.
  #
  def disable_mouse
    raise NotImplementedError
  end

  #
  # This method enables the mouse on the remote machine.
  #
  def enable_mouse
    raise NotImplementedError
  end

  #
  # This method gets the number of seconds the user has been idle from input
  # on the remote machine.
  #
  def idle_time
    raise NotImplementedError
  end

end

end; end
