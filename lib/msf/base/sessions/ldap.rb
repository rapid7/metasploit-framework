# -*- coding: binary -*-

require 'rex/post/ldap'

class Msf::Sessions::LDAP
  #
  # This interface supports basic interaction.
  #
  include Msf::Session::Basic
  include Msf::Sessions::Scriptable

  # @return [Rex::Post::LDAP::Ui::Console] The interactive console
  attr_accessor :console
  # @return [Rex::Proto::LDAP::Client] The LDAP client
  attr_accessor :client

  attr_accessor :keep_alive_thread
  
  # @return [Integer] Seconds between keepalive requests
  attr_accessor :keepalive_seconds

  attr_accessor :platform, :arch
  attr_reader :framework

  # @param[Rex::IO::Stream] rstream
  # @param [Hash] opts
  # @option opts [Rex::Proto::LDAP::Client] :client
  # @option opts [Integer] :keepalive
  def initialize(rstream, opts = {})
    @client = opts.fetch(:client)
    @keepalive_seconds = opts.fetch(:keepalive_seconds)
    self.console = Rex::Post::LDAP::Ui::Console.new(self)
    super(rstream, opts)
  end

  def cleanup
    stop_keep_alive_loop
    super
  end

  def bootstrap(datastore = {}, handler = nil)
    session = self
    session.init_ui(user_input, user_output)

    username = datastore['USERNAME']
    if username.blank?
      begin
        whoami = client.ldapwhoami
      rescue Net::LDAP::Error => e
        ilog('ldap session opened with no username and the target does not support the LDAP whoami extension')
      else
        username = whoami.delete_prefix('u:').split('\\').last
      end
    end
    @info = "LDAP #{username} @ #{@peer_info}"
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
    'ldap'
  end

  def self.can_cleanup_files
    false
  end

  #
  # Returns the session description.
  #
  def desc
    'LDAP'
  end

  def address
    @address ||= client.peerhost
  end

  def port
    @port ||= client.peerport
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
    # Call the console interaction of the ldap client and
    # pass it a block that returns whether or not we should still be
    # interacting.  This will allow the shell to abort if interaction is
    # canceled.
    console.interact { interacting != true }
    console.framework = nil

    # If the stop flag has been set, then that means the user exited.  Raise
    # the EOFError so we can drop this handle like a bad habit.
    raise EOFError if (console.stopped? == true)
  end

  def on_registered
    start_keep_alive_loop
  end

  # Start a background thread for regularly sending a no-op command to keep the connection alive
  def start_keep_alive_loop
    self.keep_alive_thread = framework.threads.spawn("LDAP-shell-keepalive-#{sid}", false) do
      loop do
        if client.last_interaction.nil?
          remaining_sleep = @keepalive_seconds
        else
          remaining_sleep = @keepalive_seconds - (Process.clock_gettime(Process::CLOCK_MONOTONIC) - client.last_interaction)
        end
        sleep(remaining_sleep)
        if (Process.clock_gettime(Process::CLOCK_MONOTONIC) - client.last_interaction) > @keepalive_seconds
          client.search_root_dse
        end
        # This should have moved last_interaction forwards
        fail if (Process.clock_gettime(Process::CLOCK_MONOTONIC) - client.last_interaction) > @keepalive_seconds
      end
    end
  end

  # Stop the background thread
  def stop_keep_alive_loop
    keep_alive_thread.kill
  end
end
