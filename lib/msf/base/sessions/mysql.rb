# -*- coding: binary -*-

require 'rex/post/mysql'

class Msf::Sessions::MySQL

  # This interface supports basic interaction.
  include Msf::Session::Basic
  include Msf::Sessions::Scriptable

  # @return [Rex::Post::MySQL::Ui::Console] The interactive console
  attr_accessor :console
  # @return [MySQL::Client]
  attr_accessor :client
  attr_accessor :platform, :arch

  # @param[Rex::IO::Stream] rstream
  # @param [Hash] opts
  def initialize(rstream, opts = {})
    @client = opts.fetch(:client)
    self.console = ::Rex::Post::MySQL::Ui::Console.new(self)
    super(rstream, opts)
  end

  # @param [Hash] datastore
  # @param [nil] handler
  # @return [String]
  def bootstrap(datastore = {}, handler = nil)
    session = self
    session.init_ui(user_input, user_output)

    @info = "MySQL #{datastore['USERNAME']} @ #{client.socket.peerinfo}"
  end

  def process_autoruns(datastore)
    ['InitialAutoRunScript', 'AutoRunScript'].each do |key|
      next if datastore[key].nil? || datastore[key].empty?

      args = Shellwords.shellwords(datastore[key])
      print_status("Session ID #{session.sid} (#{session.tunnel_to_s}) processing #{key} '#{datastore[key]}'")
      execute_script(args.shift, *args)
    end
  end

  # @return [String]
  def type
    self.class.type
  end

  # @return [String] The type of the session
  def self.type
    'mysql'
  end

  # @return [Boolean] Can the session clean up after itself
  def self.can_cleanup_files
    false
  end

  # @return [String] The session description
  def desc
    'MySQL'
  end

  # @return [Object] The peer address
  def address
    return @address if @address

    @address, @port = @client.socket.peerinfo.split(':')
    @address
  end

  # @return [Object] The peer host
  def port
    return @port if @port

    @address, @port = @client.socket.peerinfo.split(':')
    @port
  end

  # Initializes the console's I/O handles.
  #
  # @param [Object] input
  # @param [Object] output
  # @return [String]
  def init_ui(input, output)
    super(input, output)

    console.init_ui(input, output)
    console.set_log_source(log_source)
  end

  # Resets the console's I/O handles.
  #
  # @return [Object]
  def reset_ui
    console.unset_log_source
    console.reset_ui
  end


  # Exit the console
  #
  # @return [TrueClass]
  def exit
    console.stop
  end

  protected

  # Override the basic session interaction to use shell_read and
  # shell_write instead of operating on rstream directly.
  #
  # @return [Object]
  def _interact
    framework.events.on_session_interact(self)
    framework.history_manager.with_context(name: type.to_sym) { _interact_stream }
  end

  # @return [Object]
  def _interact_stream
    framework.events.on_session_interact(self)

    console.framework = framework
    # Call the console interaction of the mysql client and
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
