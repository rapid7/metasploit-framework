# -*- coding: binary -*-
module Msf
module Session
module Provider

###
#
# This interface is to be implemented by a session that is only capable of
# providing an interface to a single command shell.
#
###
module SingleCommandShell

  #
  # Initializes the command shell.
  #
  def shell_init()
    raise NotImplementedError
  end

  #
  # Reads data from the command shell.
  #
  def shell_read(length = nil)
    raise NotImplementedError
  end

  #
  # Writes data to the command shell.
  #
  def shell_write(buf)
    raise NotImplementedError
  end

  #
  # Closes the command shell.
  #
  def shell_close()
    raise NotImplementedError
  end

  def command_termination
    "\n"
  end

  #
  # Read data until we find the token
  #
  def shell_read_until_token(token, wanted_idx=0, timeout=10)
    return if timeout.to_i == 0

    if wanted_idx == 0
      parts_needed = 2
    else
      parts_needed = 1 + (wanted_idx * 2)
    end

    # Read until we get the data between two tokens or absolute timeout.
    begin
      ::Timeout.timeout(timeout) do
        buf = ''
        idx = nil
        loop do
          if (tmp = shell_read(-1))
            buf << tmp
            # see if we have the wanted idx
            unless buf.nil?
              # normalize the line endings following the token and parse them
              buf.gsub!("#{token}\n", "#{token}\r\n")
              parts = buf.split("#{token}\r\n", -1)
              if parts.length >= parts_needed
                # cause another prompt to appear (just in case)
                shell_write(command_termination)
                return parts[wanted_idx]
              end
            end
          end
        end
      end
    rescue Timeout::Error
      # This is expected in many cases
    end
    # failed to get any data or find the token!
    nil
  end

  def shell_command_token(cmd, timeout=10)
    if platform == 'windows'
      output = shell_command_token_win32(cmd, timeout)
    else
      output = shell_command_token_unix(cmd, timeout)
    end
    output
  end

  # We don't know initially whether the shell we have is one that
  # echos input back to the output stream. If it is, we need to
  # take this into account when using tokens to extract the data corresponding
  # to the command we run. For instance, if the input is not echoed, our output
  # will receive the data corresponding to the command run, followed by the token.
  # On the other hand, if it does echo, we will see the token (echoed from our input)
  # followed by the data corresponding to the command that was run, followed again
  # by the token (this time from actually being run).
  #
  # This function determines which situation we're in, and sets a variable accordingly
  # (is_echo_shell) which will persist for the duration of the session.
  def set_is_echo_shell(timeout, command_separator)
    return @is_echo_shell unless @is_echo_shell.nil?
    token = ::Rex::Text.rand_text_alpha(32)
    numeric_token = rand(0xffffffff) + 1
    cmd = "echo #{numeric_token}"
    shell_write(cmd + "#{command_separator}echo #{token}#{command_termination}")
    res = shell_read_until_token(token, 0, timeout)
    @is_echo_shell = res.include?(cmd)
  end

  def shell_command_token_win32(cmd, timeout=10)
    shell_command_token_base(cmd, timeout, '&')
  end

  def shell_command_token_unix(cmd, timeout=10)
    shell_command_token_base(cmd, timeout, ';')
  end

  #
  # Explicitly run a single command and return the output.
  # This version uses a marker to denote the end of data (instead of a timeout).
  # @param cmd [String] The command to run (will have an echo statement appended to signify the end)
  # @param timeout [Integer] The timeout in seconds for the command
  # @param command_separator [String] A string to separate commands, for the given platform
  #
  def shell_command_token_base(cmd, timeout=10, command_separator="\n")
    # read any pending data
    buf = shell_read(-1, 0.01)
    set_is_echo_shell(timeout, command_separator)
    token = ::Rex::Text.rand_text_alpha(32)

    # Send the command to the session's stdin.
    delimiter = "echo #{token}"
    if cmd.strip.end_with?(command_separator)
      # This command already ends with a delimiter - don't need to add another one
      shell_data = cmd + "#{delimiter}#{command_termination}"
    else
      shell_data = cmd + "#{command_separator}#{delimiter}#{command_termination}"
    end
    unless @is_echo_shell
      shell_data = "#{delimiter}#{command_separator}#{shell_data}"
    end
    shell_write(shell_data)
    res = shell_read_until_token(token, 1, timeout)
    res
  end


end

end
end
end
