# -*- coding:binary -*-

require 'rex/post/mssql'

class Msf::Sessions::MSSQL

  include Msf::Session::Basic
  include Msf::Sessions::Scriptable

  # @return [Rex::Post::MSSQL::Ui::Console] The interactive console
  attr_accessor :console
  # @return [MSSQL::Client] The MSSQL client
  attr_accessor :client
  attr_accessor :platform, :arch
  # @return [String] The address MSSQL is running on
  attr_accessor :address
  # @return [Integer] The port MSSQL is running on
  attr_accessor :port
  attr_reader :framework

  def initialize(rstream, opts = {})
    @client = opts.fetch(:client)
    self.console = Rex::Post::MSSQL::Ui::Console.new(self, opts)

    super(rstream, opts)
  end

  def bootstrap(datastore = {}, handler = nil)
    session = self
    session.init_ui(user_input, user_output)

    @info = "MSSQL #{datastore['USERNAME']} @ #{@peer_info}"
  end

  def execute_file(full_path, args)
    if File.extname(full_path) == '.rb'
      Rex::Script::Shell.new(self, full_path).run(args)
    else
      console.load_resource(full_path)
    end
  end

  def process_autoruns(datastore)
    ['InitialAutoRunScript', 'AutoRunScript'].each do |key|
      next if datastore[key].nil? || datastore[key].empty?

      args = Shellwords.shellwords(datastore[key])
      print_status("Session ID #{self.sid} (#{self.tunnel_to_s}) processing #{key} '#{datastore[key]}'")
      self.execute_script(args.shift, *args)
    end
  end

  def type
    self.class.type
  end

  # Returns the type of session.
  #
  def self.type
    'MSSQL'
  end

  def self.can_cleanup_files
    false
  end

  #
  # Returns the session description.
  #
  def desc
    'MSSQL'
  end

  def address
    return @address if @address

    @address, @port = client.sock.peerinfo.split(':')
    @address
  end

  def port
    return @port if @port

    @address, @port = client.sock.peerinfo.split(':')
    @port
  end

  ##
  # :category: Msf::Session::Interactive implementors
  #
  # Initializes the console's I/O handles.
  #
  def init_ui(input, output)
    self.user_input = input
    self.user_output = output
    console.init_ui(input, output)
    console.set_log_source(log_source)

    super
  end

  ##
  # :category: Msf::Session::Interactive implementors
  #
  # Resets the console's I/O handles.
  #
  def reset_ui
    console.unset_log_source
    console.reset_ui
  end

  def exit
    console.stop
  end

  ##
  # :category: Msf::Session::Interactive implementors
  #
  # Override the basic session interaction to use shell_read and
  # shell_write instead of operating on rstream directly.
  def _interact
    framework.events.on_session_interact(self)
    framework.history_manager.with_context(name: type.to_sym) do
      _interact_stream
    end
  end

  ##
  # :category: Msf::Session::Interactive implementors
  #
  def _interact_stream
    framework.events.on_session_interact(self)

    console.framework = framework
    # Call the console interaction of the MSSQL client and
    # pass it a block that returns whether or not we should still be
    # interacting.  This will allow the shell to abort if interaction is
    # canceled.
    console.interact { interacting != true }
    console.framework = nil

    # If the stop flag has been set, then that means the user exited.  Raise
    # the EOFError so we can drop this handle like a bad habit.
    raise EOFError if (console.stopped? == true)
  end

end
