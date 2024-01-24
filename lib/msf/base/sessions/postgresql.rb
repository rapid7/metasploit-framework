# -*- coding: binary -*-

require 'rex/post/postgresql'

class Msf::Sessions::PostgreSQL
  #
  # This interface supports basic interaction.
  #
  include Msf::Session::Basic
  include Msf::Sessions::Scriptable

  # @return [Rex::Post::PostgreSQL::Ui::Console] The interactive console
  attr_accessor :console
  # @return [PostgreSQL::Client]
  attr_accessor :client
  attr_accessor :platform, :arch

  # @param[Rex::IO::Stream] rstream
  # @param [Hash] opts
  # @param opts [PostgreSQL::Client] :client
  def initialize(rstream, opts = {})
    @client = opts.fetch(:client)
    @console = ::Rex::Post::PostgreSQL::Ui::Console.new(self)
    super(rstream, opts)
  end

  def bootstrap(datastore = {}, handler = nil)
    session = self
    session.init_ui(user_input, user_output)

    @info = "PostgreSQL #{datastore['USERNAME']} @ #{@peer_info}"
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

  #
  # @return [String] The type of the session
  #
  def self.type
    'PostgreSQL'
  end

  #
  # @return [Boolean] Can the session clean up after itself
  def self.can_cleanup_files
    false
  end

  #
  # @return [String] The session description
  #
  def desc
    'PostgreSQL'
  end

  def address
    return @address if @address

    @address, @port = @client.conn.peerinfo.split(':')
    @address
  end

  def port
    return @port if @port

    @address, @port = @client.conn.peerinfo.split(':')
    @port
  end

  ##
  # :category: Msf::Session::Interactive implementors
  #
  # Initializes the console's I/O handles.
  #
  def init_ui(input, output)
    super(input, output)

    console.init_ui(input, output)
    console.set_log_source(self.log_source)
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

  protected

  ##
  # :category: Msf::Session::Interactive implementors
  #
  # Override the basic session interaction to use shell_read and
  # shell_write instead of operating on rstream directly.
  def _interact
    framework.events.on_session_interact(self)
    framework.history_manager.with_context(name: type.to_sym) { _interact_stream }
  end

  ##
  # :category: Msf::Session::Interactive implementors
  #
  def _interact_stream
    framework.events.on_session_interact(self)

    console.framework = framework

    # Call the console interaction of the PostgreSQL client and
    # pass it a block that returns whether or not we should still be
    # interacting.  This will allow the shell to abort if interaction is
    # canceled.
    console.interact { interacting != true }
    console.framework = nil

    # If the stop flag has been set, then that means the user exited.  Raise
    # the EOFError so we can drop this handle like a bad habit.
    raise ::EOFError if (console.stopped? == true)
  end
end
