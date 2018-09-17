# -*- coding: binary -*-
module Msf
module Session

###
#
# This class implements an interactive session using raw input/output in
# only the most basic fashion.
#
###
module Basic

  include Session
  include Interactive

  #
  # Description of the session.
  #
  def desc
    "Basic I/O"
  end

  #
  # Basic session.
  #
  def type
    "basic"
  end

protected

  #
  # Performs the actual raw interaction with the remote side.  This can be
  # overriden by derived classes if they wish to do this another way.
  #
  def _interact
    framework.events.on_session_interact(self)
    interact_stream(rstream)
  end

end

end
end
