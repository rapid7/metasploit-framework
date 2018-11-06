if defined?(EventMachine.library_type) and EventMachine.library_type == :pure_ruby
  # assume 'em/pure_ruby' was loaded already
elsif RUBY_PLATFORM =~ /java/
  require 'java'
  require 'jeventmachine'
else
  begin
    require 'rubyeventmachine'
  rescue LoadError
    warn "Unable to load the EventMachine C extension; To use the pure-ruby reactor, require 'em/pure_ruby'"
    raise
  end
end

require 'em/version'
require 'em/pool'
require 'em/deferrable'
require 'em/future'
require 'em/streamer'
require 'em/spawnable'
require 'em/processes'
require 'em/iterator'
require 'em/buftok'
require 'em/timers'
require 'em/protocols'
require 'em/connection'
require 'em/callback'
require 'em/queue'
require 'em/channel'
require 'em/file_watch'
require 'em/process_watch'
require 'em/tick_loop'
require 'em/resolver'
require 'em/completion'
require 'em/threaded_resource'

require 'shellwords'
require 'thread'
require 'resolv'

# Top-level EventMachine namespace. If you are looking for EventMachine examples, see {file:docs/GettingStarted.md EventMachine tutorial}.
#
# ## Key methods ##
# ### Starting and stopping the event loop ###
#
# * {EventMachine.run}
# * {EventMachine.stop_event_loop}
#
# ### Implementing clients ###
#
# * {EventMachine.connect}
#
# ### Implementing servers ###
#
# * {EventMachine.start_server}
#
# ### Working with timers ###
#
# * {EventMachine.add_timer}
# * {EventMachine.add_periodic_timer}
# * {EventMachine.cancel_timer}
#
# ### Working with blocking tasks ###
#
# * {EventMachine.defer}
# * {EventMachine.next_tick}
#
# ### Efficient proxying ###
#
# * {EventMachine.enable_proxy}
# * {EventMachine.disable_proxy}
module EventMachine
  class << self
    # Exposed to allow joining on the thread, when run in a multithreaded
    # environment. Performing other actions on the thread has undefined
    # semantics (read: a dangerous endevor).
    #
    # @return [Thread]
    attr_reader :reactor_thread
  end
  @next_tick_mutex = Mutex.new
  @reactor_running = false
  @next_tick_queue = []
  @tails = []
  @threadpool = @threadqueue = @resultqueue = nil
  @all_threads_spawned = false

  # System errnos
  # @private
  ERRNOS = Errno::constants.grep(/^E/).inject(Hash.new(:unknown)) { |hash, name|
    errno = Errno.__send__(:const_get, name)
    hash[errno::Errno] = errno
    hash
  }

  # Initializes and runs an event loop. This method only returns if code inside the block passed to this method
  # calls {EventMachine.stop_event_loop}. The block is executed after initializing its internal event loop but *before* running the loop,
  # therefore this block is the right place to call any code that needs event loop to run, for example, {EventMachine.start_server},
  # {EventMachine.connect} or similar methods of libraries that use EventMachine under the hood
  # (like `EventMachine::HttpRequest.new` or `AMQP.start`).
  #
  # Programs that are run for long periods of time (e.g. servers) usually start event loop by calling {EventMachine.run}, and let it
  # run "forever". It's also possible to use {EventMachine.run} to make a single client-connection to a remote server,
  # process the data flow from that single connection, and then call {EventMachine.stop_event_loop} to stop, in other words,
  # to run event loop for a short period of time (necessary to complete some operation) and then shut it down.
  #
  # Once event loop is running, it is perfectly possible to start multiple servers and clients simultaneously: content-aware
  # proxies like [Proxymachine](https://github.com/mojombo/proxymachine) do just that.
  #
  # ## Using EventMachine with Ruby on Rails and other Web application frameworks ##
  #
  # Standalone applications often run event loop on the main thread, thus blocking for their entire lifespan. In case of Web applications,
  # if you are running an EventMachine-based app server such as [Thin](http://code.macournoyer.com/thin/) or [Goliath](https://github.com/postrank-labs/goliath/),
  # they start event loop for you. Servers like Unicorn, Apache Passenger or Mongrel occupy main Ruby thread to serve HTTP(S) requests. This means
  # that calling {EventMachine.run} on the same thread is not an option (it will result in Web server never binding to the socket).
  # In that case, start event loop in a separate thread as demonstrated below.
  #
  #
  # @example Starting EventMachine event loop in the current thread to run the "Hello, world"-like Echo server example
  #
  #   #!/usr/bin/env ruby
  #
  #   require 'rubygems' # or use Bundler.setup
  #   require 'eventmachine'
  #
  #   class EchoServer < EM::Connection
  #     def receive_data(data)
  #       send_data(data)
  #     end
  #   end
  #
  #   EventMachine.run do
  #     EventMachine.start_server("0.0.0.0", 10000, EchoServer)
  #   end
  #
  #
  # @example Starting EventMachine event loop in a separate thread
  #
  #   # doesn't block current thread, can be used with Ruby on Rails, Sinatra, Merb, Rack
  #   # and any other application server that occupies main Ruby thread.
  #   Thread.new { EventMachine.run }
  #
  #
  # @note This method blocks calling thread. If you need to start EventMachine event loop from a Web app
  #       running on a non event-driven server (Unicorn, Apache Passenger, Mongrel), do it in a separate thread like demonstrated
  #       in one of the examples.
  # @see file:docs/GettingStarted.md Getting started with EventMachine
  # @see EventMachine.stop_event_loop
  def self.run blk=nil, tail=nil, &block
    # Obsoleted the use_threads mechanism.
    # 25Nov06: Added the begin/ensure block. We need to be sure that release_machine
    # gets called even if an exception gets thrown within any of the user code
    # that the event loop runs. The best way to see this is to run a unit
    # test with two functions, each of which calls {EventMachine.run} and each of
    # which throws something inside of #run. Without the ensure, the second test
    # will start without release_machine being called and will immediately throw

    #
    if @reactor_running and @reactor_pid != Process.pid
      # Reactor was started in a different parent, meaning we have forked.
      # Clean up reactor state so a new reactor boots up in this child.
      stop_event_loop
      release_machine
      cleanup_machine
      @reactor_running = false
    end

    tail and @tails.unshift(tail)

    if reactor_running?
      (b = blk || block) and b.call # next_tick(b)
    else
      @conns = {}
      @acceptors = {}
      @timers = {}
      @wrapped_exception = nil
      @next_tick_queue ||= []
      @tails ||= []
      begin
        initialize_event_machine
        @reactor_pid = Process.pid
        @reactor_thread = Thread.current
        @reactor_running = true

        (b = blk || block) and add_timer(0, b)
        if @next_tick_queue && !@next_tick_queue.empty?
          add_timer(0) { signal_loopbreak }
        end

        # Rubinius needs to come back into "Ruby space" for GC to work,
        # so we'll crank the machine here.
        if defined?(RUBY_ENGINE) && RUBY_ENGINE == "rbx"
          while run_machine_once; end
        else
          run_machine
        end

      ensure
        until @tails.empty?
          @tails.pop.call
        end

        release_machine
        cleanup_machine
        @reactor_running = false
        @reactor_thread = nil
      end

      raise @wrapped_exception if @wrapped_exception
    end
  end

  # Sugars a common use case. Will pass the given block to #run, but will terminate
  # the reactor loop and exit the function as soon as the code in the block completes.
  # (Normally, {EventMachine.run} keeps running indefinitely, even after the block supplied to it
  # finishes running, until user code calls {EventMachine.stop})
  #
  def self.run_block &block
    pr = proc {
      block.call
      EventMachine::stop
    }
    run(&pr)
  end

  # @return [Boolean] true if the calling thread is the same thread as the reactor.
  def self.reactor_thread?
    Thread.current == @reactor_thread
  end

  # Runs the given callback on the reactor thread, or immediately if called
  # from the reactor thread. Accepts the same arguments as {EventMachine::Callback}
  def self.schedule(*a, &b)
    cb = Callback(*a, &b)
    if reactor_running? && reactor_thread?
      cb.call
    else
      next_tick { cb.call }
    end
  end

  # Forks a new process, properly stops the reactor and then calls {EventMachine.run} inside of it again, passing your block.
  def self.fork_reactor &block
    # This implementation is subject to change, especially if we clean up the relationship
    # of EM#run to @reactor_running.
    # Original patch by Aman Gupta.
    #
    Kernel.fork do
      if reactor_running?
        stop_event_loop
        release_machine
        cleanup_machine
        @reactor_running = false
        @reactor_thread = nil
      end
      run block
    end
  end

  # Clean up Ruby space following a release_machine
  def self.cleanup_machine
    if @threadpool && !@threadpool.empty?
      # Tell the threads to stop
      @threadpool.each { |t| t.exit }
      # Join the threads or bump the stragglers one more time
      @threadpool.each { |t| t.join 0.01 || t.exit }
    end
    @threadpool = nil
    @threadqueue = nil
    @resultqueue = nil
    @all_threads_spawned = false
    @next_tick_queue = []
  end

  # Adds a block to call as the reactor is shutting down.
  #
  # These callbacks are called in the _reverse_ order to which they are added.
  #
  # @example Scheduling operations to be run when EventMachine event loop is stopped
  #
  #   EventMachine.run do
  #     EventMachine.add_shutdown_hook { puts "b" }
  #     EventMachine.add_shutdown_hook { puts "a" }
  #     EventMachine.stop
  #   end
  #
  #   # Outputs:
  #   #   a
  #   #   b
  #
  def self.add_shutdown_hook &block
    @tails << block
  end

  # Adds a one-shot timer to the event loop.
  # Call it with one or two parameters. The first parameters is a delay-time
  # expressed in *seconds* (not milliseconds). The second parameter, if
  # present, must be an object that responds to :call. If 2nd parameter is not given, then you
  # can also simply pass a block to the method call.
  #
  # This method may be called from the block passed to {EventMachine.run}
  # or from any callback method. It schedules execution of the proc or block
  # passed to it, after the passage of an interval of time equal to
  # *at least* the number of seconds specified in the first parameter to
  # the call.
  #
  # {EventMachine.add_timer} is a non-blocking method. Callbacks can and will
  # be called during the interval of time that the timer is in effect.
  # There is no built-in limit to the number of timers that can be outstanding at
  # any given time.
  #
  # @example Setting a one-shot timer with EventMachine
  #
  #  EventMachine.run {
  #    puts "Starting the run now: #{Time.now}"
  #    EventMachine.add_timer 5, proc { puts "Executing timer event: #{Time.now}" }
  #    EventMachine.add_timer(10) { puts "Executing timer event: #{Time.now}" }
  #  }
  #
  # @param [Integer] delay Delay in seconds
  # @see EventMachine::Timer
  # @see EventMachine.add_periodic_timer
  def self.add_timer *args, &block
    interval = args.shift
    code = args.shift || block
    if code
      # check too many timers!
      s = add_oneshot_timer((interval.to_f * 1000).to_i)
      @timers[s] = code
      s
    end
  end

  # Adds a periodic timer to the event loop.
  # It takes the same parameters as the one-shot timer method, {EventMachine.add_timer}.
  # This method schedules execution of the given block repeatedly, at intervals
  # of time *at least* as great as the number of seconds given in the first
  # parameter to the call.
  #
  # @example Write a dollar-sign to stderr every five seconds, without blocking
  #
  #  EventMachine.run {
  #    EventMachine.add_periodic_timer( 5 ) { $stderr.write "$" }
  #  }
  #
  # @param [Integer] delay Delay in seconds
  #
  # @see EventMachine::PeriodicTimer
  # @see EventMachine.add_timer
  #
  def self.add_periodic_timer *args, &block
    interval = args.shift
    code = args.shift || block

    EventMachine::PeriodicTimer.new(interval, code)
  end


  # Cancel a timer (can be a callback or an {EventMachine::Timer} instance).
  #
  # @param [#cancel, #call] timer_or_sig A timer to cancel
  # @see EventMachine::Timer#cancel
  def self.cancel_timer timer_or_sig
    if timer_or_sig.respond_to? :cancel
      timer_or_sig.cancel
    else
      @timers[timer_or_sig] = false if @timers.has_key?(timer_or_sig)
    end
  end


  # Causes the processing loop to stop executing, which will cause all open connections and accepting servers
  # to be run down and closed. Connection termination callbacks added using {EventMachine.add_shutdown_hook}
  # will be called as part of running this method.
  #
  # When all of this processing is complete, the call to {EventMachine.run} which started the processing loop
  # will return and program flow will resume from the statement following {EventMachine.run} call.
  #
  # @example Stopping a running EventMachine event loop
  #
  #  require 'rubygems'
  #  require 'eventmachine'
  #
  #  module Redmond
  #    def post_init
  #      puts "We're sending a dumb HTTP request to the remote peer."
  #      send_data "GET / HTTP/1.1\r\nHost: www.microsoft.com\r\n\r\n"
  #    end
  #
  #    def receive_data data
  #      puts "We received #{data.length} bytes from the remote peer."
  #      puts "We're going to stop the event loop now."
  #      EventMachine::stop_event_loop
  #    end
  #
  #    def unbind
  #      puts "A connection has terminated."
  #    end
  #  end
  #
  #  puts "We're starting the event loop now."
  #  EventMachine.run {
  #    EventMachine.connect "www.microsoft.com", 80, Redmond
  #  }
  #  puts "The event loop has stopped."
  #
  #  # This program will produce approximately the following output:
  #  #
  #  # We're starting the event loop now.
  #  # We're sending a dumb HTTP request to the remote peer.
  #  # We received 1440 bytes from the remote peer.
  #  # We're going to stop the event loop now.
  #  # A connection has terminated.
  #  # The event loop has stopped.
  #
  #
  def self.stop_event_loop
    EventMachine::stop
  end

  # Initiates a TCP server (socket acceptor) on the specified IP address and port.
  #
  # The IP address must be valid on the machine where the program
  # runs, and the process must be privileged enough to listen
  # on the specified port (on Unix-like systems, superuser privileges
  # are usually required to listen on any port lower than 1024).
  # Only one listener may be running on any given address/port
  # combination. start_server will fail if the given address and port
  # are already listening on the machine, either because of a prior call
  # to {.start_server} or some unrelated process running on the machine.
  # If {.start_server} succeeds, the new network listener becomes active
  # immediately and starts accepting connections from remote peers,
  # and these connections generate callback events that are processed
  # by the code specified in the handler parameter to {.start_server}.
  #
  # The optional handler which is passed to this method is the key
  # to EventMachine's ability to handle particular network protocols.
  # The handler parameter passed to start_server must be a Ruby Module
  # that you must define. When the network server that is started by
  # start_server accepts a new connection, it instantiates a new
  # object of an anonymous class that is inherited from {EventMachine::Connection},
  # *into which your handler module have been included*. Arguments passed into start_server
  # after the class name are passed into the constructor during the instantiation.
  #
  # Your handler module may override any of the methods in {EventMachine::Connection},
  # such as {EventMachine::Connection#receive_data}, in order to implement the specific behavior
  # of the network protocol.
  #
  # Callbacks invoked in response to network events *always* take place
  # within the execution context of the object derived from {EventMachine::Connection}
  # extended by your handler module. There is one object per connection, and
  # all of the callbacks invoked for a particular connection take the form
  # of instance methods called against the corresponding {EventMachine::Connection}
  # object. Therefore, you are free to define whatever instance variables you
  # wish, in order to contain the per-connection state required by the network protocol you are
  # implementing.
  #
  # {EventMachine.start_server} is usually called inside the block passed to {EventMachine.run},
  # but it can be called from any EventMachine callback. {EventMachine.start_server} will fail
  # unless the EventMachine event loop is currently running (which is why
  # it's often called in the block suppled to {EventMachine.run}).
  #
  # You may call start_server any number of times to start up network
  # listeners on different address/port combinations. The servers will
  # all run simultaneously. More interestingly, each individual call to start_server
  # can specify a different handler module and thus implement a different
  # network protocol from all the others.
  #
  # @example
  #
  #  require 'rubygems'
  #  require 'eventmachine'
  #
  #  # Here is an example of a server that counts lines of input from the remote
  #  # peer and sends back the total number of lines received, after each line.
  #  # Try the example with more than one client connection opened via telnet,
  #  # and you will see that the line count increments independently on each
  #  # of the client connections. Also very important to note, is that the
  #  # handler for the receive_data function, which our handler redefines, may
  #  # not assume that the data it receives observes any kind of message boundaries.
  #  # Also, to use this example, be sure to change the server and port parameters
  #  # to the start_server call to values appropriate for your environment.
  #  module LineCounter
  #    MaxLinesPerConnection = 10
  #
  #    def post_init
  #      puts "Received a new connection"
  #      @data_received = ""
  #      @line_count = 0
  #    end
  #
  #    def receive_data data
  #      @data_received << data
  #      while @data_received.slice!( /^[^\n]*[\n]/m )
  #        @line_count += 1
  #        send_data "received #{@line_count} lines so far\r\n"
  #        @line_count == MaxLinesPerConnection and close_connection_after_writing
  #      end
  #    end
  #  end
  #
  #  EventMachine.run {
  #    host, port = "192.168.0.100", 8090
  #    EventMachine.start_server host, port, LineCounter
  #    puts "Now accepting connections on address #{host}, port #{port}..."
  #    EventMachine.add_periodic_timer(10) { $stderr.write "*" }
  #  }
  #
  # @param [String] server         Host to bind to.
  # @param [Integer] port          Port to bind to.
  # @param [Module, Class] handler A module or class that implements connection callbacks
  #
  # @note Don't forget that in order to bind to ports < 1024 on Linux, *BSD and Mac OS X your process must have superuser privileges.
  #
  # @see file:docs/GettingStarted.md EventMachine tutorial
  # @see EventMachine.stop_server
  def self.start_server server, port=nil, handler=nil, *args, &block
    begin
      port = Integer(port)
    rescue ArgumentError, TypeError
      # there was no port, so server must be a unix domain socket
      # the port argument is actually the handler, and the handler is one of the args
      args.unshift handler if handler
      handler = port
      port = nil
    end if port

    klass = klass_from_handler(Connection, handler, *args)

    s = if port
          start_tcp_server server, port
        else
          start_unix_server server
        end
    @acceptors[s] = [klass,args,block]
    s
  end

  # Attach to an existing socket's file descriptor. The socket may have been
  # started with {EventMachine.start_server}.
  def self.attach_server sock, handler=nil, *args, &block
    klass = klass_from_handler(Connection, handler, *args)
    sd = sock.respond_to?(:fileno) ? sock.fileno : sock
    s = attach_sd(sd)
    @acceptors[s] = [klass,args,block,sock]
    s
  end

  # Stop a TCP server socket that was started with {EventMachine.start_server}.
  # @see EventMachine.start_server
  def self.stop_server signature
    EventMachine::stop_tcp_server signature
  end

  # Start a Unix-domain server.
  #
  # Note that this is an alias for {EventMachine.start_server}, which can be used to start both
  # TCP and Unix-domain servers.
  #
  # @see EventMachine.start_server
  def self.start_unix_domain_server filename, *args, &block
    start_server filename, *args, &block
  end

  # Initiates a TCP connection to a remote server and sets up event handling for the connection.
  # {EventMachine.connect} requires event loop to be running (see {EventMachine.run}).
  #
  # {EventMachine.connect} takes the IP address (or hostname) and
  # port of the remote server you want to connect to.
  # It also takes an optional handler (a module or a subclass of {EventMachine::Connection}) which you must define, that
  # contains the callbacks that will be invoked by the event loop on behalf of the connection.
  #
  # Learn more about connection lifecycle callbacks in the {file:docs/GettingStarted.md EventMachine tutorial} and
  # {file:docs/ConnectionLifecycleCallbacks.md Connection lifecycle guide}.
  #
  #
  # @example
  #
  #  # Here's a program which connects to a web server, sends a naive
  #  # request, parses the HTTP header of the response, and then
  #  # (antisocially) ends the event loop, which automatically drops the connection
  #  # (and incidentally calls the connection's unbind method).
  #  module DumbHttpClient
  #    def post_init
  #      send_data "GET / HTTP/1.1\r\nHost: _\r\n\r\n"
  #      @data = ""
  #      @parsed = false
  #    end
  #
  #    def receive_data data
  #      @data << data
  #      if !@parsed and @data =~ /[\n][\r]*[\n]/m
  #        @parsed = true
  #        puts "RECEIVED HTTP HEADER:"
  #        $`.each {|line| puts ">>> #{line}" }
  #
  #        puts "Now we'll terminate the loop, which will also close the connection"
  #        EventMachine::stop_event_loop
  #      end
  #    end
  #
  #    def unbind
  #      puts "A connection has terminated"
  #    end
  #  end
  #
  #  EventMachine.run {
  #    EventMachine.connect "www.bayshorenetworks.com", 80, DumbHttpClient
  #  }
  #  puts "The event loop has ended"
  #
  #
  # @example Defining protocol handler as a class
  #
  #  class MyProtocolHandler < EventMachine::Connection
  #    def initialize *args
  #      super
  #      # whatever else you want to do here
  #    end
  #
  #    # ...
  #  end
  #
  #
  # @param [String] server         Host to connect to
  # @param [Integer] port          Port to connect to
  # @param [Module, Class] handler A module or class that implements connection lifecycle callbacks
  #
  # @see EventMachine.start_server
  # @see file:docs/GettingStarted.md EventMachine tutorial
  def self.connect server, port=nil, handler=nil, *args, &blk
    # EventMachine::connect initiates a TCP connection to a remote
    # server and sets up event-handling for the connection.
    # It internally creates an object that should not be handled
    # by the caller. HOWEVER, it's often convenient to get the
    # object to set up interfacing to other objects in the system.
    # We return the newly-created anonymous-class object to the caller.
    # It's expected that a considerable amount of code will depend
    # on this behavior, so don't change it.
    #
    # Ok, added support for a user-defined block, 13Apr06.
    # This leads us to an interesting choice because of the
    # presence of the post_init call, which happens in the
    # initialize method of the new object. We call the user's
    # block and pass the new object to it. This is a great
    # way to do protocol-specific initiation. It happens
    # AFTER post_init has been called on the object, which I
    # certainly hope is the right choice.
    # Don't change this lightly, because accepted connections
    # are different from connected ones and we don't want
    # to have them behave differently with respect to post_init
    # if at all possible.

    bind_connect nil, nil, server, port, handler, *args, &blk
  end

  # This method is like {EventMachine.connect}, but allows for a local address/port
  # to bind the connection to.
  #
  # @see EventMachine.connect
  def self.bind_connect bind_addr, bind_port, server, port=nil, handler=nil, *args
    begin
      port = Integer(port)
    rescue ArgumentError, TypeError
      # there was no port, so server must be a unix domain socket
      # the port argument is actually the handler, and the handler is one of the args
      args.unshift handler if handler
      handler = port
      port = nil
    end if port

    klass = klass_from_handler(Connection, handler, *args)

    s = if port
          if bind_addr
            bind_connect_server bind_addr, bind_port.to_i, server, port
          else
            connect_server server, port
          end
        else
          connect_unix_server server
        end

    c = klass.new s, *args
    @conns[s] = c
    block_given? and yield c
    c
  end

  # {EventMachine.watch} registers a given file descriptor or IO object with the eventloop. The
  # file descriptor will not be modified (it will remain blocking or non-blocking).
  #
  # The eventloop can be used to process readable and writable events on the file descriptor, using
  # {EventMachine::Connection#notify_readable=} and {EventMachine::Connection#notify_writable=}
  #
  # {EventMachine::Connection#notify_readable?} and {EventMachine::Connection#notify_writable?} can be used
  # to check what events are enabled on the connection.
  #
  # To detach the file descriptor, use {EventMachine::Connection#detach}
  #
  # @example
  #
  #  module SimpleHttpClient
  #    def notify_readable
  #      header = @io.readline
  #
  #      if header == "\r\n"
  #        # detach returns the file descriptor number (fd == @io.fileno)
  #        fd = detach
  #      end
  #    rescue EOFError
  #      detach
  #    end
  #
  #    def unbind
  #      EM.next_tick do
  #        # socket is detached from the eventloop, but still open
  #        data = @io.read
  #      end
  #    end
  #  end
  #
  #  EventMachine.run {
  #    sock = TCPSocket.new('site.com', 80)
  #    sock.write("GET / HTTP/1.0\r\n\r\n")
  #    conn = EventMachine.watch(sock, SimpleHttpClient)
  #    conn.notify_readable = true
  #  }
  #
  # @author Riham Aldakkak (eSpace Technologies)
  def EventMachine::watch io, handler=nil, *args, &blk
    attach_io io, true, handler, *args, &blk
  end

  # Attaches an IO object or file descriptor to the eventloop as a regular connection.
  # The file descriptor will be set as non-blocking, and EventMachine will process
  # receive_data and send_data events on it as it would for any other connection.
  #
  # To watch a fd instead, use {EventMachine.watch}, which will not alter the state of the socket
  # and fire notify_readable and notify_writable events instead.
  def EventMachine::attach io, handler=nil, *args, &blk
    attach_io io, false, handler, *args, &blk
  end

  # @private
  def EventMachine::attach_io io, watch_mode, handler=nil, *args
    klass = klass_from_handler(Connection, handler, *args)

    if !watch_mode and klass.public_instance_methods.any?{|m| [:notify_readable, :notify_writable].include? m.to_sym }
      raise ArgumentError, "notify_readable/writable with EM.attach is not supported. Use EM.watch(io){ |c| c.notify_readable = true }"
    end

    if io.respond_to?(:fileno)
      # getDescriptorByFileno deprecated in JRuby 1.7.x, removed in JRuby 9000
      if defined?(JRuby) && JRuby.runtime.respond_to?(:getDescriptorByFileno)
        fd = JRuby.runtime.getDescriptorByFileno(io.fileno).getChannel
      else
        fd = io.fileno
      end
    else
      fd = io
    end

    s = attach_fd fd, watch_mode
    c = klass.new s, *args

    c.instance_variable_set(:@io, io)
    c.instance_variable_set(:@watch_mode, watch_mode)
    c.instance_variable_set(:@fd, fd)

    @conns[s] = c
    block_given? and yield c
    c
  end


  # Connect to a given host/port and re-use the provided {EventMachine::Connection} instance.
  # Consider also {EventMachine::Connection#reconnect}.
  #
  # @see EventMachine::Connection#reconnect
  def self.reconnect server, port, handler
    # Observe, the test for already-connected FAILS if we call a reconnect inside post_init,
    # because we haven't set up the connection in @conns by that point.
    # RESIST THE TEMPTATION to "fix" this problem by redefining the behavior of post_init.
    #
    # Changed 22Nov06: if called on an already-connected handler, just return the
    # handler and do nothing more. Originally this condition raised an exception.
    # We may want to change it yet again and call the block, if any.

    raise "invalid handler" unless handler.respond_to?(:connection_completed)
    #raise "still connected" if @conns.has_key?(handler.signature)
    return handler if @conns.has_key?(handler.signature)

    s = if port
          connect_server server, port
        else
          connect_unix_server server
        end
    handler.signature = s
    @conns[s] = handler
    block_given? and yield handler
    handler
  end


  # Make a connection to a Unix-domain socket. This method is simply an alias for {.connect},
  # which can connect to both TCP and Unix-domain sockets. Make sure that your process has sufficient
  # permissions to open the socket it is given.
  #
  # @param [String] socketname Unix domain socket (local fully-qualified path) you want to connect to.
  #
  # @note UNIX sockets, as the name suggests, are not available on Microsoft Windows.
  def self.connect_unix_domain socketname, *args, &blk
    connect socketname, *args, &blk
  end


  # Used for UDP-based protocols. Its usage is similar to that of {EventMachine.start_server}.
  #
  # This method will create a new UDP (datagram) socket and
  # bind it to the address and port that you specify.
  # The normal callbacks (see {EventMachine.start_server}) will
  # be called as events of interest occur on the newly-created
  # socket, but there are some differences in how they behave.
  #
  # {Connection#receive_data} will be called when a datagram packet
  # is received on the socket, but unlike TCP sockets, the message
  # boundaries of the received data will be respected. In other words,
  # if the remote peer sent you a datagram of a particular size,
  # you may rely on {Connection#receive_data} to give you the
  # exact data in the packet, with the original data length.
  # Also observe that Connection#receive_data may be called with a
  # *zero-length* data payload, since empty datagrams are permitted in UDP.
  #
  # {Connection#send_data} is available with UDP packets as with TCP,
  # but there is an important difference. Because UDP communications
  # are *connectionless*, there is no implicit recipient for the packets you
  # send. Ordinarily you must specify the recipient for each packet you send.
  # However, EventMachine provides for the typical pattern of receiving a UDP datagram
  # from a remote peer, performing some operation, and then sending
  # one or more packets in response to the same remote peer.
  # To support this model easily, just use {Connection#send_data}
  # in the code that you supply for {Connection#receive_data}.
  #
  # EventMachine will provide an implicit return address for any messages sent to
  # {Connection#send_data} within the context of a {Connection#receive_data} callback,
  # and your response will automatically go to the correct remote peer.
  #
  # Observe that the port number that you supply to {EventMachine.open_datagram_socket}
  # may be zero. In this case, EventMachine will create a UDP socket
  # that is bound to an [ephemeral port](http://en.wikipedia.org/wiki/Ephemeral_port).
  # This is not appropriate for servers that must publish a well-known
  # port to which remote peers may send datagrams. But it can be useful
  # for clients that send datagrams to other servers.
  # If you do this, you will receive any responses from the remote
  # servers through the normal {Connection#receive_data} callback.
  # Observe that you will probably have issues with firewalls blocking
  # the ephemeral port numbers, so this technique is most appropriate for LANs.
  #
  # If you wish to send datagrams to arbitrary remote peers (not
  # necessarily ones that have sent data to which you are responding),
  # then see {Connection#send_datagram}.
  #
  # DO NOT call send_data from a datagram socket outside of a {Connection#receive_data} method. Use {Connection#send_datagram}.
  # If you do use {Connection#send_data} outside of a {Connection#receive_data} method, you'll get a confusing error
  # because there is no "peer," as #send_data requires (inside of {EventMachine::Connection#receive_data},
  # {EventMachine::Connection#send_data} "fakes" the peer as described above).
  #
  # @param [String]         address IP address
  # @param [String]         port    Port
  # @param [Class, Module]  handler A class or a module that implements connection lifecycle callbacks.
  def self.open_datagram_socket address, port, handler=nil, *args
    # Replaced the implementation on 01Oct06. Thanks to Tobias Gustafsson for pointing
    # out that this originally did not take a class but only a module.


    klass = klass_from_handler(Connection, handler, *args)
    s = open_udp_socket address, port.to_i
    c = klass.new s, *args
    @conns[s] = c
    block_given? and yield c
    c
  end


  # For advanced users. This function sets the default timer granularity, which by default is
  # slightly smaller than 100 milliseconds. Call this function to set a higher or lower granularity.
  # The function affects the behavior of {EventMachine.add_timer} and {EventMachine.add_periodic_timer}.
  # Most applications will not need to call this function.
  #
  # Avoid setting the quantum to very low values because that may reduce performance under some extreme conditions.
  # We recommend that you not use values lower than 10.
  #
  # This method only can be used if event loop is running.
  #
  # @param [Integer] mills New timer granularity, in milliseconds
  #
  # @see EventMachine.add_timer
  # @see EventMachine.add_periodic_timer
  # @see EventMachine::Timer
  # @see EventMachine.run
  def self.set_quantum mills
    set_timer_quantum mills.to_i
  end

  # Sets the maximum number of timers and periodic timers that may be outstanding at any
  # given time. You only need to call {.set_max_timers} if you need more than the default
  # number of timers, which on most platforms is 1000.
  #
  # @note This method has to be used *before* event loop is started.
  #
  # @param [Integer] ct Maximum number of timers that may be outstanding at any given time
  #
  # @see EventMachine.add_timer
  # @see EventMachine.add_periodic_timer
  # @see EventMachine::Timer
  def self.set_max_timers ct
    set_max_timer_count ct
  end

  # Gets the current maximum number of allowed timers
  #
  # @return [Integer] Maximum number of timers that may be outstanding at any given time
  def self.get_max_timers
    get_max_timer_count
  end

  # Returns the total number of connections (file descriptors) currently held by the reactor.
  # Note that a tick must pass after the 'initiation' of a connection for this number to increment.
  # It's usually accurate, but don't rely on the exact precision of this number unless you really know EM internals.
  #
  # @example
  #
  #  EventMachine.run {
  #    EventMachine.connect("rubyeventmachine.com", 80)
  #    # count will be 0 in this case, because connection is not
  #    # established yet
  #    count = EventMachine.connection_count
  #  }
  #
  #
  # @example
  #
  #  EventMachine.run {
  #    EventMachine.connect("rubyeventmachine.com", 80)
  #
  #    EventMachine.next_tick {
  #      # In this example, count will be 1 since the connection has been established in
  #      # the next loop of the reactor.
  #      count = EventMachine.connection_count
  #    }
  #  }
  #
  # @return [Integer] Number of connections currently held by the reactor.
  def self.connection_count
    self.get_connection_count
  end

  # The is the responder for the loopback-signalled event.
  # It can be fired either by code running on a separate thread ({EventMachine.defer}) or on
  # the main thread ({EventMachine.next_tick}).
  # It will often happen that a next_tick handler will reschedule itself. We
  # consume a copy of the tick queue so that tick events scheduled by tick events
  # have to wait for the next pass through the reactor core.
  #
  # @private
  def self.run_deferred_callbacks
    until (@resultqueue ||= []).empty?
      result,cback = @resultqueue.pop
      cback.call result if cback
    end

    # Capture the size at the start of this tick...
    size = @next_tick_mutex.synchronize { @next_tick_queue.size }
    size.times do |i|
      callback = @next_tick_mutex.synchronize { @next_tick_queue.shift }
      begin
        callback.call
      rescue
        exception_raised = true
        raise
      ensure
        # This is a little nasty. The problem is, if an exception occurs during
        # the callback, then we need to send a signal to the reactor to actually
        # do some work during the next_tick. The only mechanism we have from the
        # ruby side is next_tick itself, although ideally, we'd just drop a byte
        # on the loopback descriptor.
        next_tick {} if exception_raised
      end
    end
  end


  # EventMachine.defer is used for integrating blocking operations into EventMachine's control flow.
  # The action of {.defer} is to take the block specified in the first parameter (the "operation")
  # and schedule it for asynchronous execution on an internal thread pool maintained by EventMachine.
  # When the operation completes, it will pass the result computed by the block (if any) back to the
  # EventMachine reactor. Then, EventMachine calls the block specified in the second parameter to
  # {.defer} (the "callback"), as part of its normal event handling loop. The result computed by the
  # operation block is passed as a parameter to the callback. You may omit the callback parameter if
  # you don't need to execute any code after the operation completes. If the operation raises an
  # unhandled exception, the exception will be passed to the third parameter to {.defer} (the
  # "errback"), as part of its normal event handling loop. If no errback is provided, the exception
  # will be allowed to blow through to the main thread immediately.
  #
  # ## Caveats ##
  #
  # Note carefully that the code in your deferred operation will be executed on a separate
  # thread from the main EventMachine processing and all other Ruby threads that may exist in
  # your program. Also, multiple deferred operations may be running at once! Therefore, you
  # are responsible for ensuring that your operation code is threadsafe.
  #
  # Don't write a deferred operation that will block forever. If so, the current implementation will
  # not detect the problem, and the thread will never be returned to the pool. EventMachine limits
  # the number of threads in its pool, so if you do this enough times, your subsequent deferred
  # operations won't get a chance to run.
  #
  # The threads within the EventMachine's thread pool have abort_on_exception set to true. As a result,
  # if an unhandled exception is raised by the deferred operation and an errback is not provided, it
  # will blow through to the main thread immediately. If the main thread is within an indiscriminate
  # rescue block at that time, the exception could be handled improperly by the main thread.
  #
  # @example
  #
  #  operation = proc {
  #    # perform a long-running operation here, such as a database query.
  #    "result" # as usual, the last expression evaluated in the block will be the return value.
  #  }
  #  callback = proc {|result|
  #    # do something with result here, such as send it back to a network client.
  #  }
  #  errback = proc {|error|
  #    # do something with error here, such as re-raising or logging.
  #  }
  #
  #  EventMachine.defer(operation, callback, errback)
  #
  # @param [#call] op       An operation you want to offload to EventMachine thread pool
  # @param [#call] callback A callback that will be run on the event loop thread after `operation` finishes.
  # @param [#call] errback  An errback that will be run on the event loop thread after `operation` raises an exception.
  #
  # @see EventMachine.threadpool_size
  def self.defer op = nil, callback = nil, errback = nil, &blk
    # OBSERVE that #next_tick hacks into this mechanism, so don't make any changes here
    # without syncing there.
    #
    # Running with $VERBOSE set to true gives a warning unless all ivars are defined when
    # they appear in rvalues. But we DON'T ever want to initialize @threadqueue unless we
    # need it, because the Ruby threads are so heavyweight. We end up with this bizarre
    # way of initializing @threadqueue because EventMachine is a Module, not a Class, and
    # has no constructor.

    unless @threadpool
      @threadpool = []
      @threadqueue = ::Queue.new
      @resultqueue = ::Queue.new
      spawn_threadpool
    end

    @threadqueue << [op||blk,callback,errback]
  end


  # @private
  def self.spawn_threadpool
    until @threadpool.size == @threadpool_size.to_i
      thread = Thread.new do
        Thread.current.abort_on_exception = true
        while true
          begin
            op, cback, eback = *@threadqueue.pop
          rescue ThreadError
            $stderr.puts $!.message
            break # Ruby 2.0 may fail at Queue.pop
          end
          begin
            result = op.call
            @resultqueue << [result, cback]
          rescue Exception => error
            raise error unless eback
            @resultqueue << [error, eback]
          end
          signal_loopbreak
        end
      end
      @threadpool << thread
    end
    @all_threads_spawned = true
  end

  ##
  # Returns +true+ if all deferred actions are done executing and their
  # callbacks have been fired.
  #
  def self.defers_finished?
    return false if @threadpool and !@all_threads_spawned
    return false if @threadqueue and not @threadqueue.empty?
    return false if @resultqueue and not @resultqueue.empty?
    return false if @threadpool and @threadqueue.num_waiting != @threadpool.size
    return true
  end

  class << self
    # @private
    attr_reader :threadpool

    # Size of the EventMachine.defer threadpool (defaults to 20)
    # @return [Number]
    attr_accessor :threadpool_size
    EventMachine.threadpool_size = 20
  end

  # Schedules a proc for execution immediately after the next "turn" through the reactor
  # core. An advanced technique, this can be useful for improving memory management and/or
  # application responsiveness, especially when scheduling large amounts of data for
  # writing to a network connection.
  #
  # This method takes either a single argument (which must be a callable object) or a block.
  #
  # @param [#call] pr A callable object to run
  def self.next_tick pr=nil, &block
    # This works by adding to the @resultqueue that's used for #defer.
    # The general idea is that next_tick is used when we want to give the reactor a chance
    # to let other operations run, either to balance the load out more evenly, or to let
    # outbound network buffers drain, or both. So we probably do NOT want to block, and
    # we probably do NOT want to be spinning any threads. A program that uses next_tick
    # but not #defer shouldn't suffer the penalty of having Ruby threads running. They're
    # extremely expensive even if they're just sleeping.

    raise ArgumentError, "no proc or block given" unless ((pr && pr.respond_to?(:call)) or block)
    @next_tick_mutex.synchronize do
      @next_tick_queue << ( pr || block )
    end
    signal_loopbreak if reactor_running?
  end

  # A wrapper over the setuid system call. Particularly useful when opening a network
  # server on a privileged port because you can use this call to drop privileges
  # after opening the port. Also very useful after a call to {.set_descriptor_table_size},
  # which generally requires that you start your process with root privileges.
  #
  # This method is intended for use in enforcing security requirements, consequently
  # it will throw a fatal error and end your program if it fails.
  #
  # @param [String] username The effective name of the user whose privilege-level your process should attain.
  #
  # @note This method has no effective implementation on Windows or in the pure-Ruby
  #       implementation of EventMachine
  def self.set_effective_user username
    EventMachine::setuid_string username
  end


  # Sets the maximum number of file or socket descriptors that your process may open.
  # If you call this method with no arguments, it will simply return
  # the current size of the descriptor table without attempting to change it.
  #
  # The new limit on open descriptors **only** applies to sockets and other descriptors
  # that belong to EventMachine. It has **no effect** on the number of descriptors
  # you can create in ordinary Ruby code.
  #
  # Not available on all platforms. Increasing the number of descriptors beyond its
  # default limit usually requires superuser privileges. (See {.set_effective_user}
  # for a way to drop superuser privileges while your program is running.)
  #
  # @param [Integer] n_descriptors The maximum number of file or socket descriptors that your process may open
  # @return [Integer] The new descriptor table size.
  def self.set_descriptor_table_size n_descriptors=nil
    EventMachine::set_rlimit_nofile n_descriptors
  end



  # Runs an external process.
  #
  # @example
  #
  #  module RubyCounter
  #    def post_init
  #      # count up to 5
  #      send_data "5\n"
  #    end
  #    def receive_data data
  #      puts "ruby sent me: #{data}"
  #    end
  #    def unbind
  #      puts "ruby died with exit status: #{get_status.exitstatus}"
  #    end
  #  end
  #
  #  EventMachine.run {
  #    EventMachine.popen("ruby -e' $stdout.sync = true; gets.to_i.times{ |i| puts i+1; sleep 1 } '", RubyCounter)
  #  }
  #
  # @note This method is not supported on Microsoft Windows
  # @see EventMachine::DeferrableChildProcess
  # @see EventMachine.system
  def self.popen cmd, handler=nil, *args
    # At this moment, it's only available on Unix.
    # Perhaps misnamed since the underlying function uses socketpair and is full-duplex.

    klass = klass_from_handler(Connection, handler, *args)
    w = case cmd
        when Array
          cmd
        when String
          Shellwords::shellwords( cmd )
        end
    w.unshift( w.first ) if w.first
    s = invoke_popen( w )
    c = klass.new s, *args
    @conns[s] = c
    yield(c) if block_given?
    c
  end


  # Tells you whether the EventMachine reactor loop is currently running.
  #
  # Useful when writing libraries that want to run event-driven code, but may
  # be running in programs that are already event-driven. In such cases, if {EventMachine.reactor_running?}
  # returns false, your code can invoke {EventMachine.run} and run your application code inside
  # the block passed to that method. If this method returns true, just
  # execute your event-aware code.
  #
  # @return [Boolean] true if the EventMachine reactor loop is currently running
  def self.reactor_running?
    @reactor_running && Process.pid == @reactor_pid
  end


  # (Experimental)
  #
  # @private
  def self.open_keyboard handler=nil, *args
    klass = klass_from_handler(Connection, handler, *args)

    s = read_keyboard
    c = klass.new s, *args
    @conns[s] = c
    block_given? and yield c
    c
  end

  # EventMachine's file monitoring API. Currently supported are the following events
  # on individual files, using inotify on Linux systems, and kqueue for *BSD and Mac OS X:
  #
  # * File modified (written to)
  # * File moved/renamed
  # * File deleted
  #
  # EventMachine::watch_file takes a filename and a handler Module containing your custom callback methods.
  # This will setup the low level monitoring on the specified file, and create a new EventMachine::FileWatch
  # object with your Module mixed in. FileWatch is a subclass of {EventMachine::Connection}, so callbacks on this object
  # work in the familiar way. The callbacks that will be fired by EventMachine are:
  #
  # * file_modified
  # * file_moved
  # * file_deleted
  #
  # You can access the filename being monitored from within this object using {FileWatch#path}.
  #
  # When a file is deleted, {FileWatch#stop_watching} will be called after your file_deleted callback,
  # to clean up the underlying monitoring and remove EventMachine's reference to the now-useless {FileWatch} instance.
  # This will in turn call unbind, if you wish to use it.
  #
  # The corresponding system-level Errno will be raised when attempting to monitor non-existent files,
  # files with wrong permissions, or if an error occurs dealing with inotify/kqueue.
  #
  # @example
  #
  #  # Before running this example, make sure we have a file to monitor:
  #  # $ echo "bar" > /tmp/foo
  #
  #  module Handler
  #    def file_modified
  #      puts "#{path} modified"
  #    end
  #
  #    def file_moved
  #      puts "#{path} moved"
  #    end
  #
  #    def file_deleted
  #      puts "#{path} deleted"
  #    end
  #
  #    def unbind
  #      puts "#{path} monitoring ceased"
  #    end
  #  end
  #
  #  # for efficient file watching, use kqueue on Mac OS X
  #  EventMachine.kqueue = true if EventMachine.kqueue?
  #
  #  EventMachine.run {
  #    EventMachine.watch_file("/tmp/foo", Handler)
  #  }
  #
  #  # $ echo "baz" >> /tmp/foo    =>    "/tmp/foo modified"
  #  # $ mv /tmp/foo /tmp/oof      =>    "/tmp/foo moved"
  #  # $ rm /tmp/oof               =>    "/tmp/foo deleted"
  #
  # @note The ability to pick up on the new filename after a rename is not yet supported.
  #       Calling #path will always return the filename you originally used.
  #
  # @param [String]        filename Local path to the file to watch.
  # @param [Class, Module] handler  A class or module that implements event handlers associated with the file.
  def self.watch_file(filename, handler=nil, *args)
    klass = klass_from_handler(FileWatch, handler, *args)

    s = EM::watch_filename(filename)
    c = klass.new s, *args
    # we have to set the path like this because of how Connection.new works
    c.instance_variable_set("@path", filename)
    @conns[s] = c
    block_given? and yield c
    c
  end

  # EventMachine's process monitoring API. On Mac OS X and *BSD this method is implemented using kqueue.
  #
  # @example
  #
  #  module ProcessWatcher
  #    def process_exited
  #      put 'the forked child died!'
  #    end
  #  end
  #
  #  pid = fork{ sleep }
  #
  #  EventMachine.run {
  #    EventMachine.watch_process(pid, ProcessWatcher)
  #    EventMachine.add_timer(1){ Process.kill('TERM', pid) }
  #  }
  #
  # @param [Integer]       pid     PID of the process to watch.
  # @param [Class, Module] handler A class or module that implements event handlers associated with the file.
  def self.watch_process(pid, handler=nil, *args)
    pid = pid.to_i

    klass = klass_from_handler(ProcessWatch, handler, *args)

    s = EM::watch_pid(pid)
    c = klass.new s, *args
    # we have to set the path like this because of how Connection.new works
    c.instance_variable_set("@pid", pid)
    @conns[s] = c
    block_given? and yield c
    c
  end

  # Catch-all for errors raised during event loop callbacks.
  #
  # @example
  #
  #   EventMachine.error_handler{ |e|
  #     puts "Error raised during event loop: #{e.message}"
  #   }
  #
  # @param [#call] cb Global catch-all errback
  def self.error_handler cb = nil, &blk
    if cb or blk
      @error_handler = cb || blk
    elsif instance_variable_defined? :@error_handler
      remove_instance_variable :@error_handler
    end
  end

  # This method allows for direct writing of incoming data back out to another descriptor, at the C++ level in the reactor.
  # This is very efficient and especially useful for proxies where high performance is required. Propogating data from a server response
  # all the way up to Ruby, and then back down to the reactor to be sent back to the client, is often unnecessary and
  # incurs a significant performance decrease.
  #
  # The two arguments are instance of {EventMachine::Connection} subclasses, 'from' and 'to'. 'from' is the connection whose inbound data you want
  # relayed back out. 'to' is the connection to write it to.
  #
  # Once you call this method, the 'from' connection will no longer get receive_data callbacks from the reactor,
  # except in the case that 'to' connection has already closed when attempting to write to it. You can see
  # in the example, that proxy_target_unbound will be called when this occurs. After that, further incoming
  # data will be passed into receive_data as normal.
  #
  # Note also that this feature supports different types of descriptors: TCP, UDP, and pipes. You can relay
  # data from one kind to another, for example, feed a pipe from a UDP stream.
  #
  # @example
  #
  #  module ProxyConnection
  #    def initialize(client, request)
  #      @client, @request = client, request
  #    end
  #
  #    def post_init
  #      EM::enable_proxy(self, @client)
  #    end
  #
  #    def connection_completed
  #      send_data @request
  #    end
  #
  #    def proxy_target_unbound
  #      close_connection
  #    end
  #
  #    def unbind
  #      @client.close_connection_after_writing
  #    end
  #  end
  #
  #  module ProxyServer
  #    def receive_data(data)
  #      (@buf ||= "") << data
  #      if @buf =~ /\r\n\r\n/ # all http headers received
  #        EventMachine.connect("10.0.0.15", 80, ProxyConnection, self, data)
  #      end
  #    end
  #  end
  #
  #  EventMachine.run {
  #    EventMachine.start_server("127.0.0.1", 8080, ProxyServer)
  #  }
  #
  # @param [EventMachine::Connection] from    Source of data to be proxies/streamed.
  # @param [EventMachine::Connection] to      Destination of data to be proxies/streamed.
  # @param [Integer]                  bufsize Buffer size to use
  # @param [Integer]                  length  Maximum number of bytes to proxy.
  #
  # @see EventMachine.disable_proxy
  def self.enable_proxy(from, to, bufsize=0, length=0)
    EM::start_proxy(from.signature, to.signature, bufsize, length)
  end

  # Takes just one argument, a {Connection} that has proxying enabled via {EventMachine.enable_proxy}.
  # Calling this method will remove that functionality and your connection will begin receiving
  # data via {Connection#receive_data} again.
  #
  # @param [EventMachine::Connection] from    Source of data that is being proxied
  # @see EventMachine.enable_proxy
  def self.disable_proxy(from)
    EM::stop_proxy(from.signature)
  end

  # Retrieve the heartbeat interval. This is how often EventMachine will check for dead connections
  # that have had an inactivity timeout set via {Connection#set_comm_inactivity_timeout}.
  # Default is 2 seconds.
  #
  # @return [Integer] Heartbeat interval, in seconds
  def self.heartbeat_interval
    EM::get_heartbeat_interval
  end

  # Set the heartbeat interval. This is how often EventMachine will check for dead connections
  # that have had an inactivity timeout set via {Connection#set_comm_inactivity_timeout}.
  # Takes a Numeric number of seconds. Default is 2.
  #
  # @param [Integer] time Heartbeat interval, in seconds
  def self.heartbeat_interval=(time)
    EM::set_heartbeat_interval time.to_f
  end

  # @private
  def self.event_callback conn_binding, opcode, data
    #
    # Changed 27Dec07: Eliminated the hookable error handling.
    # No one was using it, and it degraded performance significantly.
    # It's in original_event_callback, which is dead code.
    #
    # Changed 25Jul08: Added a partial solution to the problem of exceptions
    # raised in user-written event-handlers. If such exceptions are not caught,
    # we must cause the reactor to stop, and then re-raise the exception.
    # Otherwise, the reactor doesn't stop and it's left on the call stack.
    # This is partial because we only added it to #unbind, where it's critical
    # (to keep unbind handlers from being re-entered when a stopping reactor
    # runs down open connections). It should go on the other calls to user
    # code, but the performance impact may be too large.
    #
    if opcode == ConnectionUnbound
      if c = @conns.delete( conn_binding )
        begin
          if c.original_method(:unbind).arity != 0
            c.unbind(data == 0 ? nil : EventMachine::ERRNOS[data])
          else
            c.unbind
          end
          # If this is an attached (but not watched) connection, close the underlying io object.
          if c.instance_variable_defined?(:@io) and !c.instance_variable_get(:@watch_mode)
            io = c.instance_variable_get(:@io)
            begin
              io.close
            rescue Errno::EBADF, IOError
            end
          end
        # As noted above, unbind absolutely must not raise an exception or the reactor will crash.
        # If there is no EM.error_handler, or if the error_handler retrows, then stop the reactor,
        # stash the exception in $wrapped_exception, and the exception will be raised after the
        # reactor is cleaned up (see the last line of self.run).
        rescue Exception => error
          if instance_variable_defined? :@error_handler
            begin
              @error_handler.call error
              # No need to stop unless error_handler rethrows
            rescue Exception => error
              @wrapped_exception = error
              stop
            end
          else
            @wrapped_exception = error
            stop
          end
        end
      elsif c = @acceptors.delete( conn_binding )
        # no-op
      else
        if $! # Bubble user generated errors.
          @wrapped_exception = $!
          stop
        else
          raise ConnectionNotBound, "received ConnectionUnbound for an unknown signature: #{conn_binding}"
        end
      end
    elsif opcode == ConnectionAccepted
      accep,args,blk = @acceptors[conn_binding]
      raise NoHandlerForAcceptedConnection unless accep
      c = accep.new data, *args
      @conns[data] = c
      blk and blk.call(c)
      c # (needed?)
      ##
      # The remaining code is a fallback for the pure ruby and java reactors.
      # In the C++ reactor, these events are handled in the C event_callback() in rubymain.cpp
    elsif opcode == ConnectionCompleted
      c = @conns[conn_binding] or raise ConnectionNotBound, "received ConnectionCompleted for unknown signature: #{conn_binding}"
      c.connection_completed
    elsif opcode == SslHandshakeCompleted
      c = @conns[conn_binding] or raise ConnectionNotBound, "received SslHandshakeCompleted for unknown signature: #{conn_binding}"
      c.ssl_handshake_completed
    elsif opcode == SslVerify
      c = @conns[conn_binding] or raise ConnectionNotBound, "received SslVerify for unknown signature: #{conn_binding}"
      c.close_connection if c.ssl_verify_peer(data) == false
    elsif opcode == TimerFired
      t = @timers.delete( data )
      return if t == false # timer cancelled
      t or raise UnknownTimerFired, "timer data: #{data}"
      t.call
    elsif opcode == ConnectionData
      c = @conns[conn_binding] or raise ConnectionNotBound, "received data #{data} for unknown signature: #{conn_binding}"
      c.receive_data data
    elsif opcode == LoopbreakSignalled
      run_deferred_callbacks
    elsif opcode == ConnectionNotifyReadable
      c = @conns[conn_binding] or raise ConnectionNotBound
      c.notify_readable
    elsif opcode == ConnectionNotifyWritable
      c = @conns[conn_binding] or raise ConnectionNotBound
      c.notify_writable
    end
  end

  #
  #
  # @private
  def self._open_file_for_writing filename, handler=nil
    klass = klass_from_handler(Connection, handler)

    s = _write_file filename
    c = klass.new s
    @conns[s] = c
    block_given? and yield c
    c
  end

  # @private
  def self.klass_from_handler(klass = Connection, handler = nil, *args)
    klass = if handler and handler.is_a?(Class)
      raise ArgumentError, "must provide module or subclass of #{klass.name}" unless klass >= handler
      handler
    elsif handler
      if defined?(handler::EM_CONNECTION_CLASS)
        handler::EM_CONNECTION_CLASS
      else
        handler::const_set(:EM_CONNECTION_CLASS, Class.new(klass) {include handler})
      end
    else
      klass
    end

    arity = klass.instance_method(:initialize).arity
    expected = arity >= 0 ? arity : -(arity + 1)
    if (arity >= 0 and args.size != expected) or (arity < 0 and args.size < expected)
      raise ArgumentError, "wrong number of arguments for #{klass}#initialize (#{args.size} for #{expected})"
    end

    klass
  end
end # module EventMachine

# Alias for {EventMachine}
EM = EventMachine
# Alias for {EventMachine::Protocols}
EM::P = EventMachine::Protocols
