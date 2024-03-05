# -*- coding: binary -*-

require 'rex/post/smb'

class Msf::Sessions::SMB
  #
  # This interface supports basic interaction.
  #
  include Msf::Session::Basic
  include Msf::Sessions::Scriptable

  # @return [Rex::Post::SMB::Ui::Console] The interactive console
  attr_accessor :console
  # @return [RubySMB::Client] The SMB client
  attr_accessor :client
  attr_accessor :platform, :arch
  attr_reader :framework

  # @param[Rex::IO::Stream] rstream
  # @param [Hash] opts
  # @option opts [RubySMB::Client] :client
  def initialize(rstream, opts = {})
    @client = opts.fetch(:client)
    self.console = Rex::Post::SMB::Ui::Console.new(self)
    super(rstream, opts)
  end

  def bootstrap(datastore = {}, handler = nil)
    session = self
    session.init_ui(user_input, user_output)

    @info = "SMB #{datastore['USERNAME']} @ #{@peer_info}"
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
      print_status("Session ID #{sid} (#{tunnel_to_s}) processing #{key} '#{datastore[key]}'")
      execute_script(args.shift, *args)
    end
  end

  def type
    self.class.type
  end

  # Returns the type of session.
  #
  def self.type
    'smb'
  end

  def self.can_cleanup_files
    false
  end

  #
  # Returns the session description.
  #
  def desc
    'SMB'
  end

  def address
    return @address if @address

    @address, @port = self.client.dispatcher.tcp_socket.peerinfo.split(':')
    @address
  end

  def port
    return @port if @port

    @address, @port = self.client.dispatcher.tcp_socket.peerinfo.split(':')
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
    # Call the console interaction of the smb client and
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
