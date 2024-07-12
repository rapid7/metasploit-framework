# -*- coding: binary -*-

class Msf::Sessions::Sql

  # This interface supports basic interaction.
  include Msf::Session::Basic
  include Msf::Sessions::Scriptable

  # @return console The interactive console
  attr_accessor :console
  # @return client The underlying client object used to make SQL queries
  attr_accessor :client
  attr_accessor :platform, :arch

  def process_autoruns(datastore)
    ['InitialAutoRunScript', 'AutoRunScript'].each do |key|
      next if datastore[key].nil? || datastore[key].empty?

      args = ::Shellwords.shellwords(datastore[key])
      print_status("Session ID #{sid} (#{tunnel_to_s}) processing #{key} '#{datastore[key]}'")
      execute_script(args.shift, *args)
    end
  end

  def execute_file(full_path, args)
    if File.extname(full_path) == '.rb'
      Rex::Script::Shell.new(self, full_path).run(args)
    else
      console.load_resource(full_path)
    end
  end

  # @param [String] cmd The command to execute in the context of a session using the '-c' flag.
  # @param [IO] output_object The IO where output should be written to
  # For example, 'query select version()' for a PostgreSQL session.
  def run_cmd(cmd, output_object=nil)
    # This implementation is taken from Meterpreter.
    stored_output_state = nil
    # If the user supplied an Output IO object, then we tell
    # the console to use that, while saving it's previous output/
    if output_object
      stored_output_state = console.output
      console.send(:output=, output_object)
    end
    success = console.run_single(cmd)
    # If we stored the previous output object of the channel
    # we restore it here to put everything back the way we found it
    # We re-use the conditional above, because we expect in many cases for
    # the stored state to actually be nil here.
    if output_object
      console.send(:output=, stored_output_state)
    end
    success
  end

  # @return [String]
  def type
    self.class.type
  end

  # @return [String] The type of the session
  def self.type
    raise ::NotImplementedError
  end

  # @return [Boolean] Can the session clean up after itself
  def self.can_cleanup_files
    raise ::NotImplementedError
  end

  # @return [String] The session description
  def desc
    raise ::NotImplementedError
  end

  # @return [String] The peer address
  def address
    client.peerhost
  end

  # @return [Integer] The peer port
  def port
    client.peerport
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
