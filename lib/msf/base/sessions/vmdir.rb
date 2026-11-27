# frozen_string_literal: true

require 'msf/ui/console/command_dispatcher/session'

# An authenticated VMware directory RPC connection, not an operating-system shell.
class Msf::Sessions::Vmdir
  include Msf::Session::Basic

  attr_reader :client, :console, :principal
  attr_accessor :platform, :arch

  # @param client [Msf::Exploit::Remote::Vmdir::Client] authenticated RPC association
  # @param username [String] authenticated SSO principal
  # @param key [String] negotiated SRP key
  def initialize(client, username:, key:)
    @client = client
    @key = key
    # Session#username is the local Framework owner, populated at registration.
    @principal = username
    self.platform = ''
    self.arch = ''
    @console = Console.new(self)
    super(client.socket)
  end

  # @return [String] framework session type
  def self.type
    # The session table appends platform details to the returned string.
    'vmdir'.dup
  end

  # @return [Boolean] RPC sessions have no filesystem cleanup API
  def self.can_cleanup_files
    false
  end

  # @return [String] framework session type
  def type
    self.class.type
  end

  # @return [String] session description
  def desc
    'VMware directory RPC'
  end

  # @return [Integer] authenticated, integrity-checked directory state
  def directory_state
    client.directory_state(principal, @key)
  end

  # CommandShell's registration helper calls this; OS-shell autoruns do not
  # apply to an RPC session and the module does not expose those options.
  # @param _datastore [Hash] module datastore
  # @return [nil]
  def process_autoruns(_datastore)
    nil
  end

  # @param input [Rex::Ui::Text::Input] session input
  # @param output [Rex::Ui::Text::Output] session output
  # @return [void]
  def init_ui(input, output)
    super
    console.init_ui(input, output)
  end

  # @return [void]
  def reset_ui
    console.reset_ui
    super
  end

  # @return [void]
  def exit
    console.stop
  end

  # @return [void]
  def cleanup
    console.stop
    super
  end

  protected

  def _interact
    framework.events.on_session_interact(self)
    console.run do |line|
      console.run_single(line)
      interacting != true
    end
    raise EOFError if console.stopped?
  end

  # Ctrl-C/Z must never write terminal control bytes into the RPC stream.
  def abort_foreground_supported
    false
  end

  def _suspend
    self.interacting = false
  end

  # Reuse the Framework's console, help, background, exit, resource and IRB
  # dispatchers; only the two product-specific commands are implemented here.
  class Console
    include Rex::Ui::Text::DispatcherShell

    attr_reader :session

    # @param session [Msf::Sessions::Vmdir] owning session
    def initialize(session)
      @session = session
      super('vmdir', '>')
      enstack_dispatcher(Commands)
    end

    # vmdir commands on top of the shared session command dispatcher.
    class Commands
      include Msf::Ui::Console::CommandDispatcher::Session

      # @return [Msf::Sessions::Vmdir] owning session
      def session
        shell.session
      end

      # @return [String] command group name
      def name
        'vmdir'
      end

      # @return [Hash] available console commands
      def commands
        super.merge('state' => 'Read the protected directory state', 'whoami' => 'Show the authenticated SSO principal')
      end

      # @return [void]
      def cmd_state
        print_line("Directory state: #{session.directory_state}")
      rescue IOError, Rex::ConnectionError, Rex::TimeoutError, Msf::Exploit::Remote::Vmdir::Error, OpenSSL::Cipher::CipherError => e
        print_error("Directory-state RPC failed: #{e.message}")
        elog('vmdir session RPC failed', error: e)
        shell.stop
      end

      # @return [void]
      def cmd_whoami
        print_line("Authenticated SSO principal: #{session.principal}")
      end
    end
  end
end

# An ordinary Unix shell over the Framework's SSH command stream. Retain the
# appliance API cleanup until this session closes, including after backgrounding.
class Msf::Sessions::Vmdir::Shell < Msf::Sessions::CommandShellUnix
  attr_accessor :after_close
  attr_reader :stream

  # @param stream [Net::SSH::CommandStream] owning SSH stream
  def initialize(stream)
    @stream = stream
    super(stream.lsock)
    stream.session = self
  end

  # @return [void]
  def cleanup
    return if @vcenter_closed

    @vcenter_closed = true
    begin
      # Its reader can observe our deliberate socket close during shutdown.
      stream.logger = nil
      stream.cleanup
    rescue IOError, Net::SSH::Exception => e
      elog('Could not close the vCenter SSH stream', error: e)
      user_output&.print_line("Could not close the vCenter SSH stream: #{e.message}")
    ensure
      super
      after_close&.call
      self.after_close = nil
    end
  end
end
