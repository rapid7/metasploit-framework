#!/usr/bin/env ruby
# -*- coding: binary -*-

module Rex
module Post

###
#
# This class provides generalized methods for interacting with a thread
# running in a process on a remote machine via a post-exploitation client.
#
###
class Thread

  #
  # Suspend the remote thread.
  #
  def suspend
    raise NotImplementedError
  end

  #
  # Resume execution of the remote thread.
  #
  def resume
    raise NotImplementedError
  end

  #
  # Terminate the remote thread.
  #
  def terminate
    raise NotImplementedError
  end

  #
  # Query architecture-specific register state.
  #
  def query_regs
    raise NotImplementedError
  end

  #
  # Set architecture-specific register state.
  #
  def set_regs
    raise NotImplementedError
  end

  #
  # Close resources associated with the thread.
  #
  def close
    raise NotImplementedError
  end
end

end; end
