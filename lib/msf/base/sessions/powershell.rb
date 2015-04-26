# -*- coding: binary -*-
require 'msf/base/sessions/command_shell'

class Msf::Sessions::PowerShell < Msf::Sessions::CommandShell
  #
  # Execute any specified auto-run scripts for this session
  #
  def process_autoruns(datastore)
    # Read the initial output (PS banner) and toss it)
    initial_output = shell_read(-1, 0.01)
    if initial_output =~ /running as user ([^\s]+) on ([^\s]+)/
      username = $1
      hostname = $2
    end
    # Set the session info
    self.info = "#{username} @ #{hostname}"
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
