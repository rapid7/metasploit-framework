# -*- coding: binary -*-
require 'rex/ui'
require 'rex/io/ring_buffer'

module Msf
module Session

###
#
# This class implements the stubs that are needed to provide an interactive
# session.
#
###
module Interactive

  #
  # Interactive sessions by default may interact with the local user input
  # and output.
  #
  include Rex::Ui::Interactive

  #
  # Initializes the session.
  #
  def initialize(rstream, opts={})
    # A nil is passed in the case of non-stream interactive sessions (Meterpreter)
    if rstream
      self.rstream = rstream
      self.ring    = Rex::IO::RingBuffer.new(rstream, {:size => opts[:ring_size] || 100 })
    end
    super()
  end

  #
  # Returns that, yes, indeed, this session supports going interactive with
  # the user.
  #
  def interactive?
    true
  end

  #
  # Returns the local information.
  #
  def tunnel_local
    return @local_info if @local_info
    begin
      @local_info = rstream.localinfo
    rescue ::Exception
      @local_info = '127.0.0.1'
    end
  end

  #
  # Returns the remote peer information.
  #
  def tunnel_peer
    return @peer_info if @peer_info
    begin
      @peer_info = rstream.peerinfo
    rescue ::Exception
      @peer_info = '127.0.0.1'
    end
  end

  #
  # Run an arbitrary command as if it came from user input.
  #
  def run_cmd(cmd)
  end

  #
  # Terminate the session
  #
  def kill
    self.reset_ui
    self.cleanup
    super()
  end

  #
  # Closes rstream.
  #
  def cleanup
    begin
      self.interacting = false if self.interactive?
      rstream.close if (rstream)
    rescue ::Exception
    end

    rstream = nil
    super
  end

  #
  # The remote stream handle.  Must inherit from Rex::IO::Stream.
  #
  attr_accessor :rstream

  #
  # The RingBuffer object used to allow concurrent access to this session
  #
  attr_accessor :ring

protected

  #
  # Stub method that is meant to handler interaction.
  #
  def _interact
    framework.events.on_session_interact(self)
  end

  #
  # Check to see if the user wants to abort.
  #
  def _interrupt
    begin
      user_want_abort?
    rescue Interrupt
      # The user hit ctrl-c while we were handling a ctrl-c. Ignore
    end
  end

  #
  # Check to see if we should suspend.
  #
  def _suspend
    # Ask the user if they would like to background the session
    if (prompt_yesno("Background session #{name}?") == true)
      self.interacting = false
    end
  end

  #
  # If the session reaches EOF, deregister it.
  #
  def _interact_complete
    framework.events.on_session_interact_completed()
    framework.sessions.deregister(self, "User exit")
  end

  #
  # Checks to see if the user wants to abort.
  #
  def user_want_abort?
    prompt_yesno("Abort session #{name}?")
  end

end

end
end

