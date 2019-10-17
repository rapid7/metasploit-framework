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
  # Returns the session platform.
  #
  def platform
    "win"
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
  def shell_command(cmd, timeout = 1800)
    # insert random marker
    strm = Rex::Text.rand_text_alpha(15)
    endm = Rex::Text.rand_text_alpha(15)

    # Send the shell channel's stdin.
    shell_write(";'#{strm}'\n" + cmd + "\n'#{endm}';\n")

    etime = ::Time.now.to_f + timeout

    buff = ""
    # Keep reading data until the marker has been received or the 30 minture timeout has occured
    while (::Time.now.to_f < etime)
      res = shell_read(-1, timeout)
      break unless res
      timeout = etime - ::Time.now.to_f

      buff << res
      if buff.match(/#{endm}/)
        # if you see the end marker, read the buffer from the start marker to the end and then display back to screen
        buff = buff.split(/#{strm}\r\n/)[-1]
        buff = buff.split(/#{endm}/)[0]
        buff.gsub!(/(?<=\r\n)PS [^>]*>/, '')
      end
    end
    buff
  end
end
