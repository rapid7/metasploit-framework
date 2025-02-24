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

  # Convert the executable and argument array to a command that can be run in this command shell
  # @param cmd_and_args [Array<String>] The process path and the arguments to the process
  def to_cmd(cmd_and_args)
    self.class.to_cmd(cmd_and_args)
  end

  # Convert the executable and argument array to a command that can be run in this command shell
  # @param cmd_and_args [Array<String>] The process path and the arguments to the process
  def self.to_cmd(cmd_and_args)
    # The principle here is that we want to launch a process such that it receives *exactly* what is in `args`. 
    # This means we need to:
    # - Escape all special characters
    # - Not escape environment variables
    # - Side-step any PowerShell magic
    # If someone specifically wants to use the PowerShell magic, they can use other APIs
  
    needs_wrapping_chars = ['$', '`', '(', ')', '@', '>', '<', '{','}', '&', ',', ' ', ';']
  
    result = ""
    cmd_and_args.each_with_index do |arg, index|
      needs_single_quoting = false
      if arg.include?("'")
        arg = arg.gsub("'", "''")
        needs_single_quoting = true
      end
      
      if arg.include?('"')
        # PowerShell acts weird around quotes and backslashes
        # First we need to escape backslashes immediately prior to a double-quote, because
        # they're treated differently than backslashes anywhere else
        arg = arg.gsub(/(\\+)"/, '\\1\\1"')

        # Then we can safely prepend a backslash to escape our double-quote
        arg = arg.gsub('"', '\\"')
        needs_single_quoting = true
      end
      
      needs_wrapping_chars.each do |char|
        if arg.include?(char)
          needs_single_quoting = true
        end
      end

      # PowerShell magic - https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_special_characters?view=powershell-7.4#stop-parsing-token---
      if arg == '--%'
        needs_single_quoting = true
      end

      will_be_double_quoted_by_powershell = [' ', '\t', '\v'].any? do |bad_char|
        arg.include?(bad_char)
      end

      if will_be_double_quoted_by_powershell
        # This is horrible, and I'm so so sorry.
        # If an argument ends with a series of backslashes, and it will be quoted by PowerShell when *it* launches the process (e.g. because the arg contains a space),
        # PowerShell will not correctly handle backslashes immediately preceeding the quote that it *itself* adds. So we need to be responsible for this.
        arg = arg.gsub(/(\\*)$/, '\\1\\1')
      end

      if needs_single_quoting
        arg = "'#{arg}'"
      end

      if arg == ''
        # Pass in empty strings
        arg = '\'""\''
      end
  
      if index == 0
        if needs_single_quoting
          # If the executable name (i.e. index 0) has beeen wrapped, then we'll have converted it to a string.
          # We then need to use the call operator ('&') to call it.
          # https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_operators?view=powershell-7.3#call-operator-
          result = "& #{arg}"
        else
          result = arg
        end
      else
        result = "#{result} #{arg}"
      end
    end

    result
  end

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
