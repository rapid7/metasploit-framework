# -*- coding: binary -*-
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

  include Msf::Sessions::Scriptable

  include Rex::Ui::Text::Resource

  @@irb_opts = Rex::Parser::Arguments.new(
    ['-h', '--help'] => [false, 'Help menu.'             ],
    '-e' => [true,  'Expression to evaluate.']
  )

  ##
  # :category: Msf::Session::Scriptable implementors
  #
  # Runs the shell session script or resource file.
  #
  def execute_file(full_path, args)
    if File.extname(full_path) == '.rb'
      Rex::Script::Shell.new(self, full_path).run(args)
    else
      load_resource(full_path)
    end
  end

  #
  # Returns the type of session.
  #
  def self.type
    "shell"
  end

  def self.can_cleanup_files
    true
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

  def abort_foreground_supported
    self.platform != 'windows'
  end

  ##
  # :category: Msf::Session::Provider::SingleCommandShell implementors
  #
  # The shell will have been initialized by default.
  #
  def shell_init
    return true
  end

  def bootstrap(datastore = {}, handler = nil)
    session = self

    if datastore['AutoVerifySession']
      session_info = ''

      # Read the initial output and mash it into a single line
      # Timeout set to 1 to read in banner of all payload responses (may capture prompt as well)
      # Encoding is not forced to support non ASCII shells
      if session.info.nil? || session.info.empty?
        banner = shell_read(-1, 1)
        if banner && !banner.empty?
          banner.gsub!(/[^[:print:][:space:]]+/n, "_")
          banner.strip!

          session_info = @banner = %Q{
Shell Banner:
#{banner}
-----
          }
        end
      end

      token = Rex::Text.rand_text_alphanumeric(8..24)
      response = shell_command("echo #{token}")
      unless response&.include?(token)
        dlog("Session #{session.sid} failed to respond to an echo command")
        print_error("Command shell session #{session.sid} is not valid and will be closed")
        session.kill
        return nil
      end

      # Only populate +session.info+ with a captured banner if the shell is responsive and verified
      session.info = session_info if session.info.blank?
      session
    else
      # Encrypted shells need all information read before anything is written, so we read in the banner here. However we
      # don't populate session.info with the captured value since without AutoVerify there's no way to be certain this
      # actually is a banner and not junk/malicious input
      if session.class == ::Msf::Sessions::EncryptedShell
        shell_read(-1, 0.1)
      end
    end
  end

  #
  # Return the subdir of the `documentation/` directory that should be used
  # to find usage documentation
  #
  def docs_dir
    File.join(super, 'shell_session')
  end

  #
  # List of supported commands.
  #
  def commands
    {
      'help'       => 'Help menu',
      'background' => 'Backgrounds the current shell session',
      'sessions'   => 'Quickly switch to another session',
      'resource'   => 'Run a meta commands script stored in a local file',
      'shell'      => 'Spawn an interactive shell (*NIX Only)',
      'download'   => 'Download files',
      'upload'     => 'Upload files',
      'source'     => 'Run a shell script on remote machine (*NIX Only)',
      'irb'        => 'Open an interactive Ruby shell on the current session',
      'pry'        => 'Open the Pry debugger on the current session'
    }
  end

  def cmd_help_help
    print_line "There's only so much I can do"
  end

  def cmd_help(*args)
    cmd = args.shift

    if cmd
      unless commands.key?(cmd)
        return print_error('No such command')
      end

      unless respond_to?("cmd_#{cmd}_help")
        return print_error("No help for #{cmd}, try -h")
      end

      return send("cmd_#{cmd}_help")
    end

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

    tbl << ['.<command>', "Prefix any built-in command on this list with a '.' to execute in the underlying shell (ex: .help)"]

    print(tbl.to_s)
    print("For more info on a specific command, use %grn<command> -h%clr or %grnhelp <command>%clr.\n\n")
  end

  def cmd_background_help
    print_line "Usage: background"
    print_line
    print_line "Stop interacting with this session and return to the parent prompt"
    print_line
  end

  def escape_arg(arg)
    # By default we don't know what the escaping is. It's not ideal, but subclasses should do their own appropriate escaping
    arg
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
    if args.length != 1
      print_status "Wrong number of arguments expected: 1, received: #{args.length}"
      return cmd_sessions_help
    end

    if args[0] == '-h' || args[0] == '--help'
      return cmd_sessions_help
    end

    session_id = args[0].to_i
    if session_id <= 0
      print_status 'Invalid session id'
      return cmd_sessions_help
    end

    if session_id == self.sid
      # Src == Dst
      print_status("Session #{self.name} is already interactive.")
    else
      print_status("Backgrounding session #{self.name}...")
      # store the next session id so that it can be referenced as soon
      # as this session is no longer interacting
      self.next_session = session_id
      self.interacting = false
    end
  end

  def cmd_resource(*args)
    if args.empty? || args[0] == '-h' || args[0] == '--help'
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
        print_status("Executing resource script #{good_res}")
        load_resource(good_res)
        print_status("Resource script #{good_res} complete")
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
    print_line('Pop up an interactive shell via multiple methods.')
    print_line('An interactive shell means that you can use several useful commands like `passwd`, `su [username]`')
    print_line('There are four implementations of it: ')
    print_line('\t1. using python `pty` module (default choice)')
    print_line('\t2. using `socat` command')
    print_line('\t3. using `script` command')
    print_line('\t4. upload a pty program via reverse shell')
    print_line
  end

  def cmd_shell(*args)
    if args.length == 1 && (args[0] == '-h' || args[0] == '--help')
      # One arg, and args[0] => '-h' '--help'
      return cmd_shell_help
    end

    if platform == 'windows'
      print_error('Functionality not supported on windows')
      return
    end

    # 1. Using python
    python_path = binary_exists("python") || binary_exists("python3")
    if python_path != nil
      print_status("Using `python` to pop up an interactive shell")
      # Ideally use bash for a friendlier shell, but fall back to /bin/sh if it doesn't exist
      shell_path = binary_exists("bash") || '/bin/sh'
      shell_command("#{python_path} -c \"#{ Msf::Payload::Python.create_exec_stub("import pty; pty.spawn('#{shell_path}')") } \"")
      return
    end

    # 2. Using script
    script_path = binary_exists("script")
    if script_path != nil
      print_status("Using `script` to pop up an interactive shell")
      # Payload: script /dev/null
      # Using /dev/null to make sure there is no log file on the target machine
      # Prevent being detected by the admin or antivirus software
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

  def self.binary_exists(binary, platform: nil, &block)
    if block.call('command -v command').to_s.strip == 'command'
      binary_path = block.call("command -v '#{binary}' && echo true").to_s.strip
    else
      binary_path = block.call("which '#{binary}' && echo true").to_s.strip
    end
    return nil unless binary_path.include?('true')

    binary_path.split("\n")[0].strip # removes 'true' from stdout
  end

  #
  # Returns path of a binary in PATH env.
  #
  def binary_exists(binary)
    print_status("Trying to find binary '#{binary}' on the target machine")

    binary_path = self.class.binary_exists(binary, platform: platform) do |command|
      shell_command_token(command)
    end

    if binary_path.nil?
      print_error("#{binary} not found")
    else
      print_status("Found #{binary} at #{binary_path}")
    end

    return binary_path
  end

  def cmd_download_help
    print_line("Usage: download [src] [dst]")
    print_line
    print_line("Downloads remote files to the local machine.")
    print_line("Only files are supported.")
    print_line
  end

  def cmd_download(*args)
    if args.length != 2
      # no arguments, just print help message
      return cmd_download_help
    end

    src = args[0]
    dst = args[1]

    # Check if src exists
    if !_file_transfer.file_exist?(src)
      print_error("The target file does not exist")
      return
    end

    # Get file content
    print_status("Download #{src} => #{dst}")
    content = _file_transfer.read_file(src)

    # Write file to local machine
    File.binwrite(dst, content)
    print_good("Done")

  rescue NotImplementedError => e
    print_error(e.message)
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
      # no arguments, just print help message
      return cmd_upload_help
    end

    src = args[0]
    dst = args[1]

    # Check target file exists on the target machine
    if _file_transfer.file_exist?(dst)
      print_warning("The file <#{dst}> already exists on the target machine")
      unless prompt_yesno("Overwrite the target file <#{dst}>?")
        return
      end
    end

    begin
      content = File.binread(src)
      result = _file_transfer.write_file(dst, content)
      print_good("File <#{dst}> upload finished") if result
      print_error("Error occurred while uploading <#{src}> to <#{dst}>") unless result
    rescue => e
      print_error("Error occurred while uploading <#{src}> to <#{dst}> - #{e.message}")
      elog(e)
      return
    end

  rescue NotImplementedError => e
    print_error(e.message)
  end

  def cmd_source_help
    print_line("Usage: source [file] [background]")
    print_line
    print_line("Execute a local shell script file on remote machine")
    print_line("This meta command will upload the script then execute it on the remote machine")
    print_line
    print_line("background")
    print_line("`y` represent execute the script in background, `n` represent on foreground")
  end

  def cmd_source(*args)
    if args.length != 2
      # no arguments, just print help message
      return cmd_source_help
    end

    if platform == 'windows'
      print_error('Functionality not supported on windows')
      return
    end

    background = args[1].downcase == 'y'

    local_file = args[0]
    remote_file = "/tmp/." + ::Rex::Text.rand_text_alpha(32) + ".sh"

    cmd_upload(local_file, remote_file)

    # Change file permission in case of TOCTOU
    shell_command("chmod 0600 #{remote_file}")

    if background
      print_status("Executing on remote machine background")
      print_line(shell_command("nohup sh -x #{remote_file} &"))
    else
      print_status("Executing on remote machine foreground")
      print_line(shell_command("sh -x #{remote_file}"))
    end
    print_status("Cleaning temp file on remote machine")
    shell_command("rm -rf '#{remote_file}'")
  end

  def cmd_irb_help
    print_line('Usage: irb')
    print_line
    print_line('Open an interactive Ruby shell on the current session.')
    print @@irb_opts.usage
  end

  #
  # Open an interactive Ruby shell on the current session
  #
  def cmd_irb(*args)
    expressions = []

    # Parse the command options
    @@irb_opts.parse(args) do |opt, idx, val|
      case opt
      when '-e'
        expressions << val
      when '-h'
        return cmd_irb_help
      end
    end

    session = self
    framework = self.framework

    if expressions.empty?
      print_status('Starting IRB shell...')
      print_status("You are in the \"self\" (session) object\n")
      framework.history_manager.with_context(name: :irb) do
        Rex::Ui::Text::IrbShell.new(self).run
      end
    else
      # XXX: No vprint_status here
      if framework.datastore['VERBOSE'].to_s == 'true'
        print_status("You are executing expressions in #{binding.receiver}")
      end

      expressions.each { |expression| eval(expression, binding) }
    end
  end

  def cmd_pry_help
    print_line 'Usage: pry'
    print_line
    print_line 'Open the Pry debugger on the current session.'
    print_line
  end

  #
  # Open the Pry debugger on the current session
  #
  def cmd_pry(*args)
    if args.include?('-h') || args.include?('--help')
      cmd_pry_help
      return
    end

    begin
      require 'pry'
    rescue LoadError
      print_error('Failed to load Pry, try "gem install pry"')
      return
    end

    print_status('Starting Pry shell...')
    print_status("You are in the \"self\" (session) object\n")
    Pry.config.history_load = false
    framework.history_manager.with_context(history_file: Msf::Config.pry_history, name: :pry) do
      self.pry
    end
  end

  #
  # Explicitly runs a single line command.
  #
  def run_single(cmd)
    # Do nil check for cmd (CTRL+D will cause nil error)
    return unless cmd

    begin
      arguments = Shellwords.shellwords(cmd)
      method = arguments.shift
    rescue ArgumentError => e
      # Handle invalid shellwords, such as unmatched quotes
      # See https://github.com/rapid7/metasploit-framework/issues/15912
    end

    # Built-in command
    if commands.key?(method) or ( not method.nil? and method[0] == '.' and commands.key?(method[1..-1]))
      # Handle overlapping built-ins with actual shell commands by prepending '.'
      if method[0] == '.' and commands.key?(method[1..-1])
        return shell_write(cmd[1..-1] + command_termination)
      else
        return run_builtin_cmd(method, arguments)
      end
    end

    # User input is not a built-in command, write to socket directly
    shell_write(cmd + command_termination)
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
  def shell_command(cmd, timeout=5)
    # Send the command to the session's stdin.
    shell_write(cmd + command_termination)

    etime = ::Time.now.to_f + timeout
    buff = ""

    # Keep reading data until no more data is available or the timeout is
    # reached.
    while (::Time.now.to_f < etime and (self.respond_to?(:ring) or ::IO.select([rstream], nil, nil, timeout)))
      res = shell_read(-1, 0.01)
      buff << res if res
      timeout = etime - ::Time.now.to_f
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
      rlog(rv, self.log_source) if rv && self.log_source
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
      rlog(buf, self.log_source) if self.log_source
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

  # Perform command line escaping wherein most chars are able to be escaped by quoting them,
  # but others don't have a valid way of existing inside quotes, so we need to "glue" together
  # a series of sections of the original command line; some sections inside quotes, and some outside
  # @param arg [String] The command line arg to escape
  # @param quote_requiring [Array<String>] The chars that can successfully be escaped inside quotes
  # @param unquotable_char [String] The character that can't exist inside quotes
  # @param escaped_unquotable_char [String] The escaped form of unquotable_char
  # @param quote_char [String] The char used for quoting
  def self._glue_cmdline_escape(arg, quote_requiring, unquotable_char, escaped_unquotable_char, quote_char)
    current_token = ""
    result = ""
    in_quotes = false

    arg.each_char do |char|
      if char == unquotable_char
        if in_quotes
          # This token has been in an inside-quote context, so let's properly wrap that before continuing
          current_token = "#{quote_char}#{current_token}#{quote_char}"
        end
        result += current_token
        result += escaped_unquotable_char # Escape the offending percent

        # Start a new token - we'll assume we're remaining outside quotes
        current_token = ''
        in_quotes = false
        next
      elsif quote_requiring.include?(char)
        # Oh, it turns out we should have been inside quotes for this token.
        # Let's note that, for when we actually append the token
        in_quotes = true
      end
      current_token += char
    end

    if in_quotes
      # The final token has been in an inside-quote context, so let's properly wrap that before continuing
      current_token = "#{quote_char}#{current_token}#{quote_char}"
    end
    result += current_token

    result
  end

  attr_accessor :arch
  attr_accessor :platform
  attr_accessor :max_threads
  attr_reader :banner

protected

  ##
  # :category: Msf::Session::Interactive implementors
  #
  # Override the basic session interaction to use shell_read and
  # shell_write instead of operating on rstream directly.
  def _interact
    framework.events.on_session_interact(self)
    framework.history_manager.with_context(name: self.type.to_sym) {
      _interact_stream
    }
  end

  ##
  # :category: Msf::Session::Interactive implementors
  #
  def _interact_stream
    fds = [rstream.fd, user_input.fd]

    # Displays +info+ on all session startups
    # +info+ is set to the shell banner and initial prompt in the +bootstrap+ method
    user_output.print("#{@banner}\n") if !@banner.blank? && self.interacting

    run_single('')

    while self.interacting
      sd = Rex::ThreadSafe.select(fds, nil, fds, 0.5)
      next unless sd

      if sd[0].include? rstream.fd
        user_output.print(shell_read)
      end
      if sd[0].include? user_input.fd
        run_single((user_input.gets || '').chomp("\n"))
      end
      Thread.pass
    end
  end

  # Functionality used as part of builtin commands/metashell support that isn't meant to be exposed
  # as part of the CommandShell's public API
  class FileTransfer
    include Msf::Post::File

    # @param [Msf::Sessions::CommandShell] session
    def initialize(session)
      @session = session
    end

    private

    def vprint_status(s)
      session.print_status(s)
    end

    attr_reader :session
  end

  def _file_transfer
    raise NotImplementedError.new('Session does not support file transfers.') if session_type.ends_with?(':winpty')

    FileTransfer.new(self)
  end
end

end
end
