# -*- coding: binary -*-

class Msf::Sessions::PowerShell < Msf::Sessions::CommandShell
  module Mixin
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

      buff = ''
      # Keep reading data until the marker has been received or the 30 minute timeout has occurred
      while (::Time.now.to_f < etime)
        res = shell_read(-1, timeout)
        break unless res

        timeout = etime - ::Time.now.to_f

        buff << res
        next unless buff.include?(endm)

        # if you see the end marker, read the buffer from the start marker to the end and then display back to screen
        buff = buff.split(/#{strm}\r\n/)[-1]
        buff = buff.split(endm)[0]
        buff.gsub!(/(?<=\r\n)PS [^>]*>/, '')
        return buff
      end
      buff
    end
  end

  include Mixin

  #
  # Execute any specified auto-run scripts for this session
  #
  def process_autoruns(datastore)
    # Read the username and hostname from the initial banner
    initial_output = shell_read(-1, 2)
    if initial_output =~ /running as user ([^\s]+) on ([^\s]+)/
      username = Regexp.last_match(1)
      hostname = Regexp.last_match(2)
      self.info = "#{username} @ #{hostname}"
    elsif initial_output
      self.info = initial_output.gsub(/[\r\n]/, ' ')
    end

    # Call our parent class's autoruns processing method
    super
  end

  #
  # Returns the type of session.
  #
  def self.type
    'powershell'
  end

  def self.can_cleanup_files
    true
  end

  #
  # Returns the session platform.
  #
  def platform
    'windows'
  end

  #
  # Returns the session description.
  #
  def desc
    'Powershell session'
  end

end
