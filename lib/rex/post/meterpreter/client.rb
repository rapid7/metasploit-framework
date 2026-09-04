# -*- coding: binary -*-

require 'socket'
require 'openssl'
require 'rex/thread_factory'

require 'rex/post/channel'
require 'rex/post/meterpreter/extension_mapper'
require 'rex/post/meterpreter/client_core'
require 'rex/post/meterpreter/async_window'
require 'rex/post/meterpreter/channel'
require 'rex/post/meterpreter/dependencies'
require 'rex/post/meterpreter/object_aliases'
require 'rex/post/meterpreter/packet'
require 'rex/post/meterpreter/packet_parser'
require 'rex/post/meterpreter/packet_dispatcher'
require 'rex/post/meterpreter/pivot'
require 'rex/post/meterpreter/pivot_container'

module Rex
module Post
module Meterpreter

#
# Just to get it in there...
#
module Extensions
end

###
#
# This class represents a logical meterpreter client class.  This class
# provides an interface that is compatible with the Rex post-exploitation
# interface in terms of the feature set that it attempts to expose.  This
# class is meant to drive a single meterpreter client session.
#
###
class Client

  ASYNC_LEASE_POLL_INTERVAL = 1
  ASYNC_SCHEDULE_SAFETY_MARGIN = 2 * 3600

  include Rex::Post::Channel::Container
  include Rex::Post::Meterpreter::PacketDispatcher
  include Rex::Post::Meterpreter::PivotContainer

  #
  # Extension name to class hash.
  #
  @@ext_hash = {}

  #
  # Cached auto-generated SSL certificate
  #
  @@ssl_cached_cert = nil

  #
  # Mutex to synchronize class-wide operations
  #
  @@ssl_mutex = ::Mutex.new

  #
  # Lookup the error that occurred
  #
  def self.lookup_error(code)
    code
  end

  #
  # Checks the extension hash to see if a class has already been associated
  # with the supplied extension name.
  #
  def self.check_ext_hash(name)
    @@ext_hash[name]
  end

  #
  # Stores the name to class association for the supplied extension name.
  #
  def self.set_ext_hash(name, klass)
    @@ext_hash[name] = klass
  end

  #
  # Initializes the client context with the supplied socket through
  # which communication with the server will be performed.
  #
  def initialize(sock, opts={})
    init_meterpreter(sock, opts)
  end

  #
  # Cleans up the meterpreter instance, terminating the dispatcher thread.
  #
  def cleanup_meterpreter
    if self.pivot_session
      self.pivot_session.remove_pivot_session(self.session_guid)
    end

    self.pivot_sessions.keys.each do |k|
      pivot = self.pivot_sessions[k]
      pivot.pivoted_session.kill('Pivot closed')
      pivot.pivoted_session.shutdown_passive_dispatcher
    end

    unless self.skip_cleanup
      ext.aliases.each_value do | extension |
        extension.cleanup if extension.respond_to?( 'cleanup' )
      end
    end

    dispatcher_thread.kill if dispatcher_thread

    unless self.skip_cleanup
      core.shutdown rescue nil
    end

    shutdown_passive_dispatcher

    shutdown_tlv_logging
  end

  #
  # Wrap the given packet data with any prefixes and suffixes that are stored in
  # the associated C2 profile server configuration (if it exists) and handle
  # encoding of data
  #
  def wrap_packet(raw_bytes)
    if self.c2_profile
      raw_bytes = self.c2_profile.wrap_outbound_get(raw_bytes)
    end

    raw_bytes
  end

  #
  # Unwrap the given packet data from any prefixes and suffixes that are stored in
  # the associated C2 profile client configuration (if it exists) and handle
  # decoding of data
  #
  def unwrap_packet(raw_bytes)
    if self.c2_profile
      raw_bytes = self.c2_profile.unwrap_inbound_post(raw_bytes)
    end

    raw_bytes
  end

  #
  # Initializes the meterpreter client instance
  #
  def init_meterpreter(sock,opts={})
    self.sock         = sock
    self.parser       = PacketParser.new
    self.ext          = ObjectAliases.new
    self.ext_aliases  = ObjectAliases.new
    self.alive        = true
    self.target_id    = opts[:target_id]
    self.capabilities = opts[:capabilities] || {}
    self.commands     = []
    self.last_checkin = ::Time.now

    self.conn_id      = opts[:conn_id]
    self.url          = opts[:url]
    self.ssl          = opts[:ssl]

    self.c2_profile = opts[:c2_profile]

    self.pivot_session = opts[:pivot_session]
    if self.pivot_session
      self.expiration   = self.pivot_session.expiration
      self.comm_timeout = self.pivot_session.comm_timeout
      self.retry_total  = self.pivot_session.retry_total
      self.retry_wait   = self.pivot_session.retry_wait
    else
      self.expiration   = opts[:expiration]
      self.comm_timeout = opts[:comm_timeout]
      self.retry_total  = opts[:retry_total]
      self.retry_wait   = opts[:retry_wait]
      self.passive_dispatcher = opts[:passive_dispatcher]
    end

    self.response_timeout = opts[:timeout] || self.class.default_timeout
    self.send_keepalives  = true

    # TODO: Clarify why we don't allow unicode to be set in initial options
    # self.encode_unicode   = opts.has_key?(:encode_unicode) ? opts[:encode_unicode] : true
    self.encode_unicode = false

    self.aes_key      = nil
    self.session_guid = opts[:session_guid] || "\x00" * 16

    # The SSL certificate is being passed down as a file path
    if opts[:ssl_cert]
      if ! ::File.exist? opts[:ssl_cert]
        elog("SSL certificate at #{opts[:ssl_cert]} does not exist and will be ignored")
      else
        # Load the certificate the same way that SslTcpServer does it
        self.ssl_cert = ::File.read(opts[:ssl_cert])
      end
    end
    # Use the debug build if specified
    self.debug_build = opts[:debug_build]


    # Protocol specific dispatch mixins go here, this may be neater with explicit Client classes
    opts[:dispatch_ext].each {|dx| self.extend(dx)} if opts[:dispatch_ext]
    initialize_passive_dispatcher if opts[:passive_dispatcher]

    register_extension_alias('core', ClientCore.new(self))

    initialize_inbound_handlers
    initialize_channels
    initialize_pivots

    # Register the channel and pivot inbound packet handlers
    register_inbound_handler(Rex::Post::Meterpreter::Channel)
    register_inbound_handler(Rex::Post::Meterpreter::Pivot)

    monitor_socket
  end

  def swap_sock_plain_to_ssl
    # Create a new SSL session on the existing socket
    ctx = generate_ssl_context()
    ssl = OpenSSL::SSL::SSLSocket.new(sock, ctx)

    # Use non-blocking OpenSSL operations on Windows
    if !( ssl.respond_to?(:accept_nonblock) and Rex::Compat.is_windows )
      ssl.accept
    else
      begin
        ssl.accept_nonblock

      # Ruby 1.8.7 and 1.9.0/1.9.1 uses a standard Errno
      rescue ::Errno::EAGAIN, ::Errno::EWOULDBLOCK
          IO::select(nil, nil, nil, 0.10)
          retry

      # Ruby 1.9.2+ uses IO::WaitReadable/IO::WaitWritable
      rescue ::Exception => e
        if ::IO.const_defined?('WaitReadable') and e.kind_of?(::IO::WaitReadable)
          IO::select( [ ssl ], nil, nil, 0.10 )
          retry
        end

        if ::IO.const_defined?('WaitWritable') and e.kind_of?(::IO::WaitWritable)
          IO::select( nil, [ ssl ], nil, 0.10 )
          retry
        end

        raise e
      end
    end

    self.sock.extend(Rex::Socket::SslTcp)
    self.sock.sslsock = ssl
    self.sock.sslctx  = ctx
    self.sock.sslhash = Rex::Text.sha1_raw(ctx.cert.to_der)

    tag = self.sock.get_once(-1, 30)
    if(not tag or tag !~ /^GET \//)
      raise RuntimeError, "Could not read the HTTP hello token"
    end
  end

  def swap_sock_ssl_to_plain
    # Remove references to the SSLSocket and Context
    self.sock.sslsock.close
    self.sock.sslsock = nil
    self.sock.sslctx  = nil
    self.sock.sslhash = nil
    self.sock = self.sock.fd
    self.sock.extend(::Rex::Socket::Tcp)
  end

  def generate_ssl_context

    ctx = nil
    ssl_cert_info = nil

    loop do

      # Load a custom SSL certificate if one has been specified
      if self.ssl_cert
        wlog("Loading custom SSL certificate for Meterpreter session")
        ssl_cert_info = Rex::Socket::SslTcpServer.ssl_parse_pem(self.ssl_cert)
        wlog("Loaded custom SSL certificate for Meterpreter session")
        break
      end

      # Generate a certificate if necessary and cache it
      if ! @@ssl_cached_cert
        @@ssl_mutex.synchronize do
          wlog("Generating SSL certificate for Meterpreter sessions")
          @@ssl_cached_cert = Rex::Socket::SslTcpServer.ssl_generate_certificate
          wlog("Generated SSL certificate for Meterpreter sessions")
        end
      end

      # Use the cached certificate
      ssl_cert_info = @@ssl_cached_cert
      break
    end

    # Create a new context for each session
    ctx = OpenSSL::SSL::SSLContext.new()
    ctx.key = ssl_cert_info[0]
    ctx.cert = ssl_cert_info[1]
    ctx.extra_chain_cert = ssl_cert_info[2]
    ctx.options = 0
    ctx.session_id_context = Rex::Text.rand_text(16)

    ctx
  end

  ##
  #
  # Accessors
  #
  ##

  #
  # Returns the default timeout that request packets will use when
  # waiting for a response.
  #
  def Client.default_timeout
    return 300
  end

  ##
  #
  # Alias processor
  #
  ##

  #
  # Translates unhandled methods into registered extension aliases
  # if a matching extension alias exists for the supplied symbol.
  #
  def method_missing(symbol, *args)
    #$stdout.puts("method_missing: #{symbol}")
    self.ext_aliases.aliases[symbol.to_s]
  end

  ##
  #
  # Extension registration
  #
  ##

  #
  # Loads the client half of the supplied extension and initializes it as a
  # registered extension that can be reached through client.ext.[extension].
  #
  def add_extension(name, commands=[])
    self.commands.concat(commands)

    # Check to see if this extension has already been loaded.
    if ((klass = self.class.check_ext_hash(name.downcase)) == nil)
      klass = Rex::Post::Meterpreter::ExtensionMapper.get_extension_klass(name)
      # Save the module name to class association now that the code is
      # loaded.
      self.class.set_ext_hash(name.downcase, klass)
    end

    # Create a new instance of the extension
    inst = klass.new(self)

    self.ext.aliases[inst.name] = inst

    return true
  end

  #
  # Deregisters an extension alias of the supplied name.
  #
  def deregister_extension(name)
    self.ext.aliases.delete(name)
  end

  #
  # Enumerates all of the loaded extensions.
  #
  def each_extension(&block)
    self.ext.aliases.each(block)
  end

  #
  # Registers an aliased extension that can be referenced through
  # client.name.
  #
  def register_extension_alias(name, ext)
    self.ext_aliases.aliases[name] = ext
    # Whee!  Syntactic sugar, where art thou?
    #
    # Create an instance method on this object called +name+ that returns
    # +ext+.  We have to do it this way instead of simply
    # self.class.class_eval so that other meterpreter sessions don't get
    # extension methods when this one does
    (class << self; self; end).class_eval do
      define_method(name.to_sym) do
        ext
      end
    end
    ext
  end

  #
  # Registers zero or more aliases that are provided in an array.
  #
  def register_extension_aliases(aliases)
    aliases.each { |a|
      register_extension_alias(a['name'], a['ext'])
    }
  end

  #
  # Deregisters a previously registered extension alias.
  #
  def deregister_extension_alias(name)
    self.ext_aliases.aliases.delete(name)
  end

  #
  # Dumps the extension tree.
  #
  def dump_extension_tree()
    items = []
    items.concat(self.ext.dump_alias_tree('client.ext'))
    items.concat(self.ext_aliases.dump_alias_tree('client'))

    return items.sort
  end

  #
  # Encodes (or not) a UTF-8 string
  #
  def unicode_filter_encode(str)
    self.encode_unicode ? Rex::Text.unicode_filter_encode(str) : str
  end

  #
  # Decodes (or not) a UTF-8 string
  #
  def unicode_filter_decode(str)
    self.encode_unicode ? Rex::Text.unicode_filter_decode(str) : str
  end

  #
  # The extension alias under which all extensions can be accessed by name.
  # For example:
  #
  #    client.ext.stdapi
  #
  #
  attr_reader   :ext
  #
  # The socket the client is communicating over.
  #
  attr_reader   :sock
  #
  # The timeout value to use when waiting for responses.
  #
  attr_accessor :response_timeout
  #
  # Whether to send pings every so often to determine liveness.
  #
  attr_accessor :send_keepalives
  #
  # Whether this session is alive.  If the socket is disconnected or broken,
  # this will be false
  #
  attr_accessor :alive
  #
  # The unique target identifier for this payload
  #
  attr_accessor :target_id
  #
  # The libraries available to this meterpreter server
  #
  attr_accessor :capabilities
  #
  # The Connection ID
  #
  attr_accessor :conn_id
  #
  # The Connect URL
  #
  attr_accessor :url
  #
  # Use SSL (HTTPS)
  #
  attr_accessor :ssl
  #
  # Use this SSL Certificate (unified PEM)
  #
  attr_accessor :ssl_cert
  #
  # The Session Expiration Timeout
  #
  attr_accessor :expiration
  #
  # The Communication Timeout
  #
  attr_accessor :comm_timeout
  #
  # The total time for retrying connections
  #
  attr_accessor :retry_total
  #
  # The time to wait between retry attempts
  #
  attr_accessor :retry_wait
  #
  # The Passive Dispatcher
  #
  attr_accessor :passive_dispatcher
  #
  # Reference to a session to pivot through
  #
  attr_accessor :pivot_session
  #
  # Flag indicating whether to hex-encode UTF-8 file names and other strings
  #
  attr_accessor :encode_unicode
  #
  # A list of the commands
  #
  attr_reader :commands
  #
  # The timestamp of the last received response
  #
  attr_accessor :last_checkin
  #
  # Reference to the c2 profile instance associated with this connection, if any.
  #
  attr_accessor :c2_profile
  #
  # Whether or not to use a debug build for loaded extensions
  #
  attr_accessor :debug_build
  #
  # Whether async mode is currently enabled on this session
  #
  attr_accessor :async_mode_enabled

  # Locally stored async config values (applied when async mode is enabled)
  def async_config
    @async_config ||= { poll_interval: 60, jitter: 0, work_start: 0, work_end: 24, work_days: 0x7F, lease_ttl: 300, job_timeout: 86400 }
  end

  def async_mode_enabled?
    !!self.async_mode_enabled
  end

  # Target-side wall-clock sample, populated at session bootstrap and refreshed
  # opportunistically from async check-in responses. Shape:
  #   { target_unix_ts:, target_local_ts:, utc_offset:, sampled_at: }
  # Nil when the payload doesn't support {ClientCore#get_target_time} or when
  # the sample hasn't been taken yet.
  attr_accessor :target_time_sample

  # Whether the target has acknowledged an active async job lease.
  attr_reader :async_lease_enabled

  def async_lease_enabled?
    return false unless @async_lease_enabled
    return true unless @async_lease_deadline

    active = Process.clock_gettime(Process::CLOCK_MONOTONIC) < @async_lease_deadline
    self.async_lease_enabled = false unless active
    active
  end

  def async_lease_renewed(ttl)
    self.async_lease_enabled = true
    @async_lease_deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + ttl
  end

  def async_lease_enabled=(enabled)
    @async_lease_enabled = enabled
    @async_lease_deadline = nil unless enabled
  end

  # Estimated target-local wall clock right now, as a UTC-flavored Time whose
  # #hour and #wday read in the target's local frame.
  def target_time_now
    s = @target_time_sample
    return nil unless s && s[:target_local_ts] && s[:sampled_at]

    elapsed = ::Time.now - s[:sampled_at]
    ::Time.at(s[:target_local_ts] + elapsed).utc
  end

  # Target UTC offset in seconds (east positive), or 0 when unknown.
  def target_utc_offset
    @target_time_sample&.dig(:utc_offset) || 0
  end

  def target_time_sample_age
    sampled_at = @target_time_sample&.dig(:sampled_at)
    sampled_at ? ::Time.now - sampled_at : nil
  end

  # Seconds until the target's next allowed poll window opens, given the
  # current async work_start/work_end/work_days config. See
  # {Rex::Post::Meterpreter::AsyncWindow.seconds_until_next_window}.
  def async_seconds_until_next_window(now = target_time_now)
    return nil unless now

    cfg = async_config
    AsyncWindow.seconds_until_next_window(now, cfg[:work_start], cfg[:work_end], cfg[:work_days])
  end

  # Clamp a Meterpreter request timeout when async mode is enabled. Job-lease
  # requests only need to cover rapid polling. Scheduled requests must safely
  # survive the longest valid work-window gap, including clock/DST drift.
  def async_response_timeout(timeout)
    return timeout unless async_mode_enabled? && timeout

    minimum = if async_lease_enabled?
                ASYNC_LEASE_POLL_INTERVAL * 3 + 10
              else
                cfg = async_config
                poll = cfg[:poll_interval].to_i
                worst_case = poll + (poll * cfg[:jitter].to_i / 100)
                AsyncWindow::MAXIMUM_GAP + ASYNC_SCHEDULE_SAFETY_MARGIN + worst_case * 3 + 10
              end
    [timeout.to_i, minimum].max
  end

  # Run a block while maintaining an explicit target-side rapid-poll lease.
  # The target drops the lease automatically when renewals stop.
  def with_async_lease
    ttl = async_config[:lease_ttl].to_i
    enabled = core.async_lease(enabled: true, ttl: ttl)
    raise Rex::Post::Meterpreter::RequestError.new(COMMAND_ID_CORE_ASYNC_LEASE, 'The target refused the async job lease') unless enabled

    start_async_lease_renewer(ttl)
    yield
  ensure
    stop_async_lease_renewer
    unless ::Thread.current[:msf_async_forced_stop]
      begin
        core.async_lease(enabled: false, ttl: ttl, wait: false)
      rescue ::StandardError => e
        dlog("Unable to release async job lease: #{e.message}", 'meterpreter/async')
      end
    end
    self.async_lease_enabled = false
  end

  def start_async_lease_renewer(ttl)
    @async_lease_mutex ||= ::Mutex.new
    @async_lease_condition ||= ::ConditionVariable.new
    @async_lease_mutex.synchronize { @async_lease_stopping = false }
    renew_interval = [ttl / 3, 10].max

    @async_lease_thread = Rex::ThreadFactory.spawn('AsyncLeaseRenewer', false) do
      loop do
        stopping = @async_lease_mutex.synchronize do
          @async_lease_condition.wait(@async_lease_mutex, renew_interval)
          @async_lease_stopping
        end
        break if stopping

        begin
          core.async_lease(enabled: true, ttl: ttl, timeout: ttl)
        rescue ::StandardError => e
          dlog("Async job lease renewal failed: #{e.message}", 'meterpreter/async')
        end
      end
    end
  end

  def stop_async_lease_renewer
    return unless @async_lease_thread

    @async_lease_mutex.synchronize do
      @async_lease_stopping = true
      @async_lease_condition.broadcast
    end
    @async_lease_thread.join(5)
    if @async_lease_thread.alive?
      @async_lease_thread.kill
      @async_lease_thread.join
    end
    @async_lease_thread = nil
  end

  #
  # A dedicated console used by the async worker thread to execute queued
  # commands. It has its own output buffer and dispatcher stack so nothing
  # it does can race with the operator's interactive shell. Rebuild it if
  # the main shell's dispatcher stack (extensions) has changed since the
  # last call.
  #
  # @param main_shell [Rex::Post::Meterpreter::Ui::Console] the interactive
  #   shell whose dispatcher stack should be mirrored.
  # @return [Rex::Post::Meterpreter::Ui::Console]
  #
  def async_shell(main_shell)
    core_klass = Rex::Post::Meterpreter::Ui::Console::CommandDispatcher::Core
    main_core = main_shell.dispatcher_stack.find { |d| d.is_a?(core_klass) }
    main_extensions = main_core ? main_core.instance_variable_get(:@extensions).dup : []

    if @async_shell.nil? || @async_shell_extensions != main_extensions
      shell = Rex::Post::Meterpreter::Ui::Console.new(self)

      # Wire the async shell to a BidirectionalPipe for both input and output.
      # A single Pipe object serves both roles (borrowed from Msf::Ui::Web),
      # which means:
      #   - modules that expect a non-nil user_input (e.g. reading via gets)
      #     get a valid IO instead of nil
      #   - the same pipe collects everything the module or command prints
      #     via a named subscriber ("async"), which we drain per run
      # This is safer than a bare Output::Buffer + nil input, especially when
      # Msf::SessionCompatibility#setup calls session.init_ui(input, output)
      # during post-module execution.
      pipe = Rex::Ui::Text::BidirectionalPipe.new
      # Msf module runners (e.g. cmd_run's run_simple path) check
      # `LocalOutput.prompting?` before writing status. BidirectionalPipe
      # doesn't define it - WebConsole subclasses to add it. Add it here
      # as a singleton method to avoid defining a whole subclass.
      pipe.define_singleton_method(:prompting?) { false }
      pipe.create_subscriber('async')
      shell.init_ui(pipe, pipe)
      shell.instance_variable_set(:@async_worker, true)
      shell.instance_variable_set(:@async_pipe, pipe)

      # Re-load each extension on the async shell using the same code path as
      # the main shell. Each extension class's initialize enstacks any child
      # dispatchers itself (e.g. Stdapi enstacks Fs, Net, Sys, ...), so we
      # must NOT enstack children directly or we get duplicates.
      async_core = shell.dispatcher_stack.find { |d| d.is_a?(core_klass) }
      main_extensions.each { |mod| async_core.send(:add_extension_client, mod) }

      @async_shell = shell
      @async_shell_extensions = main_extensions
    end
    @async_shell
  end

protected
  attr_accessor :parser, :ext_aliases # :nodoc:
  attr_writer   :ext, :sock # :nodoc:
  attr_writer   :commands # :nodoc:
end

end; end; end
