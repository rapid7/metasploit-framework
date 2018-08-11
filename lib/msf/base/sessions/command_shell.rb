# -*- coding: binary -*-
require 'msf/base'
require 'msf/base/sessions/scriptable'
require 'shellwords'
require 'rex/text/table'


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

  include Rex::Ui::Text::Resource

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
    @cleanup = false
    datastore = opts[:datastore]
    if datastore && !datastore["CommandShellCleanupCommand"].blank?
      @cleanup_command = datastore["CommandShellCleanupCommand"]
    end
    super
  end

  #
  # Returns the session description.
  #
  def desc
    "Command shell"
  end

  ##
  # :category: Msf::Session::Provider::SingleCommandShell implementors
  #
  # The shell will have been initialized by default.
  #
  def shell_init
    return true
  end

  #
  # List of supported commands.
  #
  def commands
    {
        'help'         =>  'Help menu',
        'background'   => 'Backgrounds the current shell session',
        'sessions'     => 'Quickly switch to another session',
        'resource'     => 'Run the commands stored in a file',
        'shell'        => 'Spawn an interactive shell',
    }
  end

  def cmd_help(*args)
    columns = ['Command', 'Description']
    tbl = Rex::Text::Table.new(
      'Header'  => 'Meta shell commands',
      'Prefix'  => "\n",
      'Postfix' => "\n",
      'Indent'  => 4,
      'Columns' => columns,
      'SortIndex' => -1
    )
    commands.each do |key, value|
      tbl << [key, value]
    end
    print(tbl.to_s)
  end

  def cmd_background_help
    print_line "Usage: background"
    print_line
    print_line "Stop interacting with this session and return to the parent prompt"
    print_line
  end

  def cmd_background(*args)
    if !args.empty?
      # We assume that background does not need arguments
      # If user input does not follow this specification
      # Then show help (Including '-h' '--help'...)
      return cmd_background_help
    end

    if prompt_yesno("Background session #{name}?")
      self.interacting = false
    end
  end

  def cmd_sessions_help
    print_line('Usage: sessions <id>')
    print_line
    print_line('Interact with a different session Id.')
    print_line('This command only accepts one positive numeric argument.')
    print_line('This works the same as calling this from the MSF shell: sessions -i <session id>')
    print_line
  end

  def cmd_sessions(*args)
    if args.length.zero? || args[0].to_i <= 0
      # No args
      return cmd_sessions_help
    end

    if args.length == 1 && (args[1] == '-h' || args[1] == 'help')
      # One arg, and args[1] => '-h' '-H' 'help'
      return cmd_sessions_help
    end

    if args.length != 1
      # More than one argument
      return cmd_sessions_help
    end

    if args[0].to_s == self.name.to_s
      # Src == Dst
      print_status("Session #{self.name} is already interactive.")
    else
      print_status("Backgrounding session #{self.name}...")
      # store the next session id so that it can be referenced as soon
      # as this session is no longer interacting
      self.next_session = args[0]
      self.interacting = false
    end
  end

  def cmd_resource(*args)
    if args.empty?
      cmd_resource_help
      return false
    end

    args.each do |res|
      good_res = nil
      if res == '-'
        good_res = res
      elsif ::File.exist?(res)
        good_res = res
      elsif
        # let's check to see if it's in the scripts/resource dir (like when tab completed)
      [
          ::Msf::Config.script_directory + ::File::SEPARATOR + 'resource' + ::File::SEPARATOR + 'meterpreter',
          ::Msf::Config.user_script_directory + ::File::SEPARATOR + 'resource' + ::File::SEPARATOR + 'meterpreter'
      ].each do |dir|
        res_path = ::File::join(dir, res)
        if ::File.exist?(res_path)
          good_res = res_path
          break
        end
      end
      end
      if good_res
        load_resource(good_res)
      else
        print_error("#{res} is not a valid resource file")
        next
      end
    end
  end

  def cmd_resource_help
    print_line "Usage: resource path1 [path2 ...]"
    print_line
    print_line "Run the commands stored in the supplied files. (- for stdin, press CTRL+D to end input from stdin)"
    print_line "Resource files may also contain ERB or Ruby code between <ruby></ruby> tags."
    print_line
  end

  def cmd_shell_help()
    print_line('Usage: shell')
    print_line
    print_line('Pop up an interactive shell via multi methods.')
    print_line('An interactive shell means that you can use several useful commands like `passwd`, `su [username]`')
    print_line('There are three implementation of it: ')
    print_line('\t1. using python `pty` module (default choice)')
    print_line('\t2. using `socat` command')
    print_line('\t3. using `script` command')
    print_line('\t4. upload a pty program via reverse shell')
    print_line
  end

  def cmd_shell(*args)
    if args.length == 1 && (args[1] == '-h' || args[1] == 'help')
      # One arg, and args[1] => '-h' '-H' 'help'
      return cmd_sessions_help
    end
    # TODO implementation of other method described in the `cmd_shell_help` method.
    # Why `/bin/sh` not `/bin/bash`, some machine may not have `/bin/bash` installed, just in case. 
    shell_command('python -c "import pty; pty.spawn(\'/bin/sh\')"')
  end
  
  #
  # Explicitly runs a single line command.
  #
  def run_single(cmd)
    # Do nil check for cmd (CTRL+D will cause nil error)
    return unless cmd

    arguments = cmd.split(' ')
    method    = arguments.shift

    # Built-in command
    if commands.key?(method)
      return run_builtin_cmd(method, arguments)
    end

    # User input is not a built-in command, write to socket directly
    shell_write(cmd)
  end

  #
  # Run built-in command
  #
  def run_builtin_cmd(method, arguments)
    # Dynamic function call
    self.send('cmd_' + method, *arguments)
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
    return unless buf

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
    return if @cleanup

    @cleanup = true
    if rstream
      if !@cleanup_command.blank?
        # this is a best effort, since the session is possibly already dead
        shell_command_token(@cleanup_command) rescue nil

        # we should only ever cleanup once
        @cleanup_command = nil
      end

      # this is also a best-effort
      rstream.close rescue nil
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
      next unless sd

      if sd[0].include? rstream.fd
        user_output.print(shell_read)
      end
      if sd[0].include? user_input.fd
        run_single(user_input.gets)
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