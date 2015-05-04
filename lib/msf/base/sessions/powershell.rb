# -*- coding: binary -*-
require 'msf/base/sessions/command_shell'

class Msf::Sessions::PowerShell < Msf::Sessions::CommandShell
  #
  # Execute any specified auto-run scripts for this session
  #
  def process_autoruns(datastore)

    # Read the username and hostname from the initial banner
    initial_output = shell_read(-1, 0.01)
    if initial_output =~ /running as user ([^\s]+) on ([^\s]+)/
      username = $1
      hostname = $2
      self.info = "#{username} @ #{hostname}"
    else
      self.info = initial_output.gsub(/[\r\n]/, ' ')
    end

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

  #
  # Takes over the shell_command of the parent
  #
  def shell_command(cmd)
    # Send the command to the session's stdin.
    shell_write(cmd + "\n")

    timeo = 5
    etime = ::Time.now.to_f + timeo
    buff = ""

    # Keep reading data until no more data is available or the timeout is
    # reached.
    while (::Time.now.to_f < etime and (self.respond_to?(:ring) or ::IO.select([rstream], nil, nil, timeo)))
      res = shell_read(-1, 0.01)
      res.gsub!(/PS .*>/, '')
      buff << res if res
      timeo = etime - ::Time.now.to_f
    end

    buff
  end
end
