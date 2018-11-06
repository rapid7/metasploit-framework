# -*- coding: binary -*-
require 'rex/ui'

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
      intent = user_want_abort?
      # Judge the user wants to abort the reverse shell session 
      # Or just want to abort the process running on the target machine
      # If the latter, just send ASCII Control Character \u0003 (End of Text) to the socket fd
      # The character will be handled by the line dicipline program of the pseudo-terminal on target machine
      # It will send the SEGINT singal to the foreground process
      if !intent
        # TODO: Check the shell is interactive or not
        # If the current shell is not interactive, the ASCII Control Character will not work
        if !(self.platform=="windows" && self.type =="shell")
          print_status("Aborting foreground process in the shell session")
          self.rstream.write("\u0003")
        end
        return
      end
    rescue Interrupt
      # The user hit ctrl-c while we were handling a ctrl-c. Ignore
    end
    p ""
  end

  def _usr1
    # A simple signal to exit vim in reverse shell
    # Just for fun
    # Make sure you have already executed `shell` meta-shell command to pop up an interactive shell
    self.rstream.write("\x1B\x1B\x1B:q!\r")
  end

  #
  # Check to see if we should suspend.
  #
  def _suspend
    # Ask the user if they would like to background the session
    intent = prompt_yesno("Background session #{name}?")
    if !intent
      # User does not want to background the current session
      # Assuming the target is *nix, we'll forward CTRL-Z to the foreground process on the target
      if !(self.platform=="windows" && self.type =="shell")
        print_status("Backgrounding foreground process in the shell session")
        self.rstream.write("\u001A")
      end
      return
    end
    self.interacting = false
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
