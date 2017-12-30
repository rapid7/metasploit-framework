# -*- coding: binary -*-
require 'msf/base'
require 'msf/base/sessions/scriptable'
require 'shellwords'

module Msf
module Sessions

###
#
# This class provides basic interaction with a command shell on the remote
# endpoint.  This session is initialized with a stream that will be used
# as the pipe for reading and writing the command shell.
#
###
class CommandShell

  #
  # This interface supports basic interaction.
  #
  include Msf::Session::Basic

  #
  # This interface supports interacting with a single command shell.
  #
  include Msf::Session::Provider::SingleCommandShell

  include Msf::Session::Scriptable


  ##
  # :category: Msf::Session::Scriptable implementors
  #
  # Executes the supplied script, must be specified as full path.
  #
  # Msf::Session::Scriptable implementor
  #
  def execute_file(full_path, args)
    o = Rex::Script::Shell.new(self, full_path)
    o.run(args)
  end

  #
  # Returns the type of session.
  #
  def self.type
    "shell"
  end

  def initialize(conn, opts = {})
    self.platform ||= ""
    self.arch     ||= ""
    self.max_threads = 1
    datastore = opts[:datastore]
    if datastore && !datastore["CommandShellCleanupCommand"].blank?
      @cleanup_command = opts[:datastore]["CommandShellCleanupCommand"]
    end
    super
  end

  #
  # Returns the session description.
  #
  def desc
    "Command shell"
  end

  #
  # Explicitly runs a command.
  #
  def run_cmd(cmd)
    shell_command(cmd)
  end

  #
  # Calls the class method.
  #
  def type
    self.class.type
  end

  ##
  # :category: Msf::Session::Provider::SingleCommandShell implementors
  #
  # The shell will have been initialized by default.
  #
  def shell_init
    return true
  end

  ##
  # :category: Msf::Session::Provider::SingleCommandShell implementors
  #
  # Explicitly run a single command, return the output.
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
      buff << res if res
      timeo = etime - ::Time.now.to_f
    end

    buff
  end

  ##
  # :category: Msf::Session::Provider::SingleCommandShell implementors
  #
  # Read from the command shell.
  #
  def shell_read(length=-1, timeout=1)
    begin
      rv = rstream.get_once(length, timeout)
      framework.events.on_session_output(self, rv) if rv
      return rv
    rescue ::Rex::SocketError, ::EOFError, ::IOError, ::Errno::EPIPE => e
      #print_error("Socket error: #{e.class}: #{e}")
      shell_close
      raise e
    end
  end

  ##
  # :category: Msf::Session::Provider::SingleCommandShell implementors
  #
  # Writes to the command shell.
  #
  def shell_write(buf)
    return if not buf

    begin
      framework.events.on_session_command(self, buf.strip)
      rstream.write(buf)
    rescue ::Rex::SocketError, ::EOFError, ::IOError, ::Errno::EPIPE => e
      #print_error("Socket error: #{e.class}: #{e}")
      shell_close
      raise e
    end
  end

  ##
  # :category: Msf::Session::Provider::SingleCommandShell implementors
  #
  # Closes the shell.
  # Note: parent's 'self.kill' method calls cleanup below.
  #
  def shell_close()
    self.kill
  end

  ##
  # :category: Msf::Session implementors
  #
  # Closes the shell.
  #
  def cleanup
    if rstream
      if !@cleanup_command.blank?
        shell_command_token(@cleanup_command, 10)
      end
      rstream.close
      rstream = nil
    end
    super
  end

  #
  # Execute any specified auto-run scripts for this session
  #
  def process_autoruns(datastore)
    # Read the initial output and mash it into a single line
    if (not self.info or self.info.empty?)
      initial_output = shell_read(-1, 0.01)
      if (initial_output)
        initial_output.force_encoding("ASCII-8BIT") if initial_output.respond_to?(:force_encoding)
        initial_output.gsub!(/[\x00-\x08\x0b\x0c\x0e-\x19\x7f-\xff]+/n,"_")
        initial_output.gsub!(/[\r\n\t]+/, ' ')
        initial_output.strip!

        # Set the inital output to .info
        self.info = initial_output
      end
    end

    if datastore['InitialAutoRunScript'] && !datastore['InitialAutoRunScript'].empty?
      args = Shellwords.shellwords( datastore['InitialAutoRunScript'] )
      print_status("Session ID #{sid} (#{tunnel_to_s}) processing InitialAutoRunScript '#{datastore['InitialAutoRunScript']}'")
      execute_script(args.shift, *args)
    end

    if (datastore['AutoRunScript'] && datastore['AutoRunScript'].empty? == false)
      args = Shellwords.shellwords( datastore['AutoRunScript'] )
      print_status("Session ID #{sid} (#{tunnel_to_s}) processing AutoRunScript '#{datastore['AutoRunScript']}'")
      execute_script(args.shift, *args)
    end
  end

  attr_accessor :arch
  attr_accessor :platform
  attr_accessor :max_threads

protected

  ##
  # :category: Msf::Session::Interactive implementors
  #
  # Override the basic session interaction to use shell_read and
  # shell_write instead of operating on rstream directly.
  def _interact
    framework.events.on_session_interact(self)
    _interact_stream
  end

  ##
  # :category: Msf::Session::Interactive implementors
  #
  def _interact_stream
    fds = [rstream.fd, user_input.fd]
    while self.interacting
      sd = Rex::ThreadSafe.select(fds, nil, fds, 0.5)
      next if not sd

      if sd[0].include? rstream.fd
        user_output.print(shell_read)
      end
      if sd[0].include? user_input.fd
        shell_write(user_input.gets)
      end
      Thread.pass
    end
  end
end

class CommandShellWindows < CommandShell
  def initialize(*args)
    self.platform = "windows"
    super
  end
  def shell_command_token(cmd,timeout = 10)
    shell_command_token_win32(cmd,timeout)
  end
end

class CommandShellUnix < CommandShell
  def initialize(*args)
    self.platform = "unix"
    super
  end
  def shell_command_token(cmd,timeout = 10)
    shell_command_token_unix(cmd,timeout)
  end
end

end
end

