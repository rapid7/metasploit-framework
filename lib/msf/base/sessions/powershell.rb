# -*- coding: binary -*-
require 'msf/base/sessions/command_shell'

class Msf::Sessions::PowerShell < Msf::Sessions::CommandShell
  #
  # Execute any specified auto-run scripts for this session
  #
  def process_autoruns(datastore)
    # Read the initial output (PS banner) and toss it)
    initial_output = shell_read(-1, 0.01)
    # TODO: send command for getting the username
    # TODO: parse out the username and set it to a variable
    # TODO: send command for getting the hostname
    # TODO: parse out the hostname and set it to a variable
    # Set the session info
    self.info = initial_output
    # Call our parent class's autoruns processing method
    super
  end
  #
  # Returns the type of session.
  #
  def self.type
    "powershell"
  end

  #
  # Returns the session description.
  #
  def desc
    "Powershell session"
  end
end
