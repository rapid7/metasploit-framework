#--
#
# Author:: Francis Cianfrocca (gmail: blackhedd)
# Homepage::  http://rubyeventmachine.com
# Date:: 8 Apr 2006
# 
# See EventMachine and EventMachine::Connection for documentation and
# usage examples.
#
#----------------------------------------------------------------------------
#
# Copyright (C) 2006-07 by Francis Cianfrocca. All Rights Reserved.
# Gmail: blackhedd
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of either: 1) the GNU General Public License
# as published by the Free Software Foundation; either version 2 of the
# License, or (at your option) any later version; or 2) Ruby's License.
# 
# See the file COPYING for complete licensing information.
#
#---------------------------------------------------------------------------
#
# 


#-- Select in a library based on a global variable.
# PROVISIONALLY commented out this whole mechanism which selects
# a pure-Ruby EM implementation if the extension is not available.
# I expect this will cause a lot of people's code to break, as it
# exposes misconfigurations and path problems that were masked up
# till now. The reason I'm disabling it is because the pure-Ruby
# code will have problems of its own, and it's not nearly as fast
# anyway. Suggested by a problem report from Moshe Litvin. 05Jun07.
#
# 05Dec07: Re-enabled the pure-ruby mechanism, but without the automatic
# fallback feature that tripped up Moshe Litvin. We shouldn't fail over to
# the pure Ruby version because it's possible that the user intended to
# run the extension but failed to do so because of a compilation or
# similar error. So we require either a global variable or an environment
# string be set in order to select the pure-Ruby version.
#


unless defined?($eventmachine_library)
  $eventmachine_library = ENV['EVENTMACHINE_LIBRARY'] || :cascade
end
$eventmachine_library = $eventmachine_library.to_sym

case $eventmachine_library
when :pure_ruby
  require 'pr_eventmachine'
when :extension
  require 'rubyeventmachine'
when :java
  require 'jeventmachine'
else # :cascade
  # This is the case that most user code will take.
  # Prefer the extension if available.
  begin
    if RUBY_PLATFORM =~ /java/
      require 'java'
      require 'jeventmachine'
      $eventmachine_library = :java
    else
      require 'rubyeventmachine'
      $eventmachine_library = :extension
    end
  rescue LoadError
    warn "# EventMachine fell back to pure ruby mode" if $DEBUG
    require 'pr_eventmachine'
    $eventmachine_library = :pure_ruby
  end
end

require "em/version"
require 'em/deferrable'
require 'em/future'
require 'em/streamer'
require 'em/spawnable'
require 'em/processes'
require 'em/buftok'
require 'em/timers'
require 'em/protocols'
require 'em/connection'
require 'em/callback'
require 'em/queue'
require 'em/channel'
require 'em/file_watch'
require 'em/process_watch'

require 'shellwords'
require 'thread'

# == Introduction
# EventMachine provides a fast, lightweight framework for implementing
# Ruby programs that can use the network to communicate with other
# processes. Using EventMachine, Ruby programmers can easily connect
# to remote servers and act as servers themselves. EventMachine does not
# supplant the Ruby IP libraries. It does provide an alternate technique
# for those applications requiring better performance, scalability,
# and discipline over the behavior of network sockets, than is easily
# obtainable using the built-in libraries, especially in applications
# which are structurally well-suited for the event-driven programming model.
#
# EventMachine provides a perpetual event-loop which your programs can
# start and stop. Within the event loop, TCP network connections are
# initiated and accepted, based on EventMachine methods called by your
# program. You also define callback methods which are called by EventMachine
# when events of interest occur within the event-loop.
#
# User programs will be called back when the following events occur:
# * When the event loop accepts network connections from remote peers
# * When data is received from network connections
# * When connections are closed, either by the local or the remote side
# * When user-defined timers expire
#
# == Usage example
#
# Here's a fully-functional echo server implemented in EventMachine:
#
#  require 'eventmachine'
#
#  module EchoServer
#    def post_init
#      puts "-- someone connected to the echo server!"
#    end
#
#    def receive_data data
#      send_data ">>>you sent: #{data}"
#      close_connection if data =~ /quit/i
#    end
#
#    def unbind
#      puts "-- someone disconnected from the echo server!"
#    end
#  end
#
#  EventMachine::run {
#    EventMachine::start_server "127.0.0.1", 8081, EchoServer
#  }
#
# What's going on here? Well, we have defined the module EchoServer to
# implement the semantics of the echo protocol (more about that shortly).
# The last three lines invoke the event-machine itself, which runs forever
# unless one of your callbacks terminates it. The block that you supply
# to EventMachine::run contains code that runs immediately after the event
# machine is initialized and before it starts looping. This is the place
# to open up a TCP server by specifying the address and port it will listen
# on, together with the module that will process the data.
# 
# Our EchoServer is extremely simple as the echo protocol doesn't require
# much work. Basically you want to send back to the remote peer whatever
# data it sends you. We'll dress it up with a little extra text to make it
# interesting. Also, we'll close the connection in case the received data
# contains the word "quit."
# 
# So what about this module EchoServer? Well, whenever a network connection
# (either a client or a server) starts up, EventMachine instantiates an anonymous
# class, that your module has been mixed into. Exactly one of these class
# instances is created for each connection. Whenever an event occurs on a
# given connection, its corresponding object automatically calls specific
# instance methods which your module may redefine. The code in your module
# always runs in the context of a class instance, so you can create instance
# variables as you wish and they will be carried over to other callbacks
# made on that same connection.
# 
# Looking back up at EchoServer, you can see that we've defined the method
# receive_data which (big surprise) is called whenever data has been received
# from the remote end of the connection. Very simple. We get the data
# (a String object) and can do whatever we wish with it. In this case,
# we use the method send_data to return the received data to the caller,
# with some extra text added in. And if the user sends the word "quit,"
# we'll close the connection with (naturally) close_connection.
# (Notice that closing the connection doesn't terminate the processing loop,
# or change the fact that your echo server is still accepting connections!) 
#
# == Questions and Futures
# Would it be useful for EventMachine to incorporate the Observer pattern
# and make use of the corresponding Ruby <tt>observer</tt> package?
# Interesting thought.
#
module EventMachine
  class <<self
    # Exposed to allow joining on the thread, when run in a multithreaded
    # environment. Performing other actions on the thread has undefined
    # semantics.
    attr_reader :reactor_thread
  end
  @next_tick_mutex = Mutex.new
  @reactor_running = false
  @next_tick_queue = nil
  @threadpool = nil
  

  # EventMachine::run initializes and runs an event loop.
  # This method only returns if user-callback code calls stop_event_loop.
  # Use the supplied block to define your clients and servers.
  # The block is called by EventMachine::run immediately after initializing
  # its internal event loop but <i>before</i> running the loop.
  # Therefore this block is the right place to call start_server if you
  # want to accept connections from remote clients.
  #
  # For programs that are structured as servers, it's usually appropriate
  # to start an event loop by calling EventMachine::run, and let it
  # run forever. It's also possible to use EventMachine::run to make a single
  # client-connection to a remote server, process the data flow from that
  # single connection, and then call stop_event_loop to force EventMachine::run
  # to return. Your program will then continue from the point immediately
  # following the call to EventMachine::run.
  #
  # You can of course do both client and servers simultaneously in the same program.
  # One of the strengths of the event-driven programming model is that the
  # handling of network events on many different connections will be interleaved,
  # and scheduled according to the actual events themselves. This maximizes
  # efficiency.
  #
  # === Server usage example
  #
  # See EventMachine.start_server
  #
  # === Client usage example
  #
  # See EventMachine.connect
  #
  #--
  # Obsoleted the use_threads mechanism.
  # 25Nov06: Added the begin/ensure block. We need to be sure that release_machine
  # gets called even if an exception gets thrown within any of the user code
  # that the event loop runs. The best way to see this is to run a unit
  # test with two functions, each of which calls EventMachine#run and each of
  # which throws something inside of #run. Without the ensure, the second test
  # will start without release_machine being called and will immediately throw
  # a C++ runtime error.
  #
  def self.run blk=nil, tail=nil, &block
    @tails ||= []
    tail and @tails.unshift(tail)

    if reactor_running?
      (b = blk || block) and b.call # next_tick(b)
    else
      @conns = {}
      @acceptors = {}
      @timers = {}
      @wrapped_exception = nil
      @next_tick_queue ||= []
      begin
        @reactor_running = true
        initialize_event_machine
        (b = blk || block) and add_timer(0, b)
        if @next_tick_queue && !@next_tick_queue.empty?
          add_timer(0) { signal_loopbreak }
        end
        @reactor_thread = Thread.current
        run_machine
      ensure
        until @tails.empty?
          @tails.pop.call
        end

        begin
          release_machine
        ensure
          if @threadpool
            @threadpool.each { |t| t.exit }
            @threadpool.each do |t|
              next unless t.alive?
              # ruby 1.9 has no kill!
              t.respond_to?(:kill!) ? t.kill! : t.kill
            end
            @threadqueue = nil
            @resultqueue = nil
            @threadpool = nil
          end

          @next_tick_queue = nil
        end
        @reactor_running = false
        @reactor_thread = nil
      end

      raise @wrapped_exception if @wrapped_exception
    end
  end

  # Sugars a common use case. Will pass the given block to #run, but will terminate
  # the reactor loop and exit the function as soon as the code in the block completes.
  # (Normally, #run keeps running indefinitely, even after the block supplied to it
  # finishes running, until user code calls #stop.)
  #
  def self.run_block &block
    pr = proc {
      block.call
      EventMachine::stop
    }
    run(&pr)
  end

  # Returns true if the calling thread is the same thread as the reactor.
  def self.reactor_thread?
    Thread.current == @reactor_thread
  end

  # Runs the given callback on the reactor thread, or immediately if called
  # from the reactor thread. Accepts the same arguments as EM::Callback
  def self.schedule(*a, &b)
    cb = Callback(*a, &b)
    if reactor_running? && reactor_thread?
      cb.call
    else
      next_tick { cb.call }
    end
  end

  # fork_reactor forks a new process and calls EM#run inside of it, passing your block.
  #--
  # This implementation is subject to change, especially if we clean up the relationship
  # of EM#run to @reactor_running.
  # Original patch by Aman Gupta.
  #
  def self.fork_reactor &block
    Kernel.fork do
      if self.reactor_running?
        self.stop_event_loop
        self.release_machine
        self.instance_variable_set( '@reactor_running', false )
      end
      self.run block
    end
  end

  # EventMachine#add_timer adds a one-shot timer to the event loop.
  # Call it with one or two parameters. The first parameters is a delay-time
  # expressed in <i>seconds</i> (not milliseconds). The second parameter, if
  # present, must be a proc object. If a proc object is not given, then you
  # can also simply pass a block to the method call.
  #
  # EventMachine#add_timer may be called from the block passed to EventMachine#run
  # or from any callback method. It schedules execution of the proc or block
  # passed to add_timer, after the passage of an interval of time equal to
  # <i>at least</i> the number of seconds specified in the first parameter to
  # the call.
  #
  # EventMachine#add_timer is a <i>non-blocking</i> call. Callbacks can and will
  # be called during the interval of time that the timer is in effect.
  # There is no built-in limit to the number of timers that can be outstanding at
  # any given time.
  #
  # === Usage example
  #
  # This example shows how easy timers are to use. Observe that two timers are
  # initiated simultaneously. Also, notice that the event loop will continue
  # to run even after the second timer event is processed, since there was
  # no call to EventMachine#stop_event_loop. There will be no activity, of
  # course, since no network clients or servers are defined. Stop the program
  # with Ctrl-C.
  #
  #  EventMachine::run {
  #    puts "Starting the run now: #{Time.now}"
  #    EventMachine::add_timer 5, proc { puts "Executing timer event: #{Time.now}" }
  #    EventMachine::add_timer( 10 ) { puts "Executing timer event: #{Time.now}" }
  #  }
  #
  #
  # Also see EventMachine::Timer
  #--
  # Changed 04Oct06: We now pass the interval as an integer number of milliseconds.
  #
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

  # EventMachine#add_periodic_timer adds a periodic timer to the event loop.
  # It takes the same parameters as the one-shot timer method, EventMachine#add_timer.
  # This method schedules execution of the given block repeatedly, at intervals
  # of time <i>at least</i> as great as the number of seconds given in the first
  # parameter to the call.
  # 
  # === Usage example
  #
  # The following sample program will write a dollar-sign to stderr every five seconds.
  # (Of course if the program defined network clients and/or servers, they would
  # be doing their work while the periodic timer is counting off.)
  #
  #  EventMachine::run {
  #    EventMachine::add_periodic_timer( 5 ) { $stderr.write "$" }
  #  }
  #
  #
  # Also see EventMachine::PeriodicTimer
  #
  def self.add_periodic_timer *args, &block
    interval = args.shift
    code = args.shift || block

    EventMachine::PeriodicTimer.new(interval, code)
  end

  # Cancel a timer using its signature. You can also use EventMachine::Timer#cancel
  #
  def self.cancel_timer timer_or_sig
    if timer_or_sig.respond_to? :cancel
      timer_or_sig.cancel
    else
      @timers[timer_or_sig] = false if @timers.has_key?(timer_or_sig)
    end
  end


  # stop_event_loop may called from within a callback method
  # while EventMachine's processing loop is running.
  # It causes the processing loop to stop executing, which
  # will cause all open connections and accepting servers
  # to be run down and closed. <i>Callbacks for connection-termination
  # will be called</i> as part of the processing of stop_event_loop.
  # (There currently is no option to panic-stop the loop without
  # closing connections.) When all of this processing is complete,
  # the call to EventMachine::run which started the processing loop
  # will return and program flow will resume from the statement
  # following EventMachine::run call.
  #
  # === Usage example
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
  #  EventMachine::run {
  #    EventMachine::connect "www.microsoft.com", 80, Redmond
  #  }
  #  puts "The event loop has stopped."
  #  
  # This program will produce approximately the following output:
  #
  #  We're starting the event loop now.
  #  We're sending a dumb HTTP request to the remote peer.
  #  We received 1440 bytes from the remote peer.
  #  We're going to stop the event loop now.
  #  A connection has terminated.
  #  The event loop has stopped.
  #
  #
  def self.stop_event_loop
    EventMachine::stop
  end

  # EventMachine::start_server initiates a TCP server (socket
  # acceptor) on the specified IP address and port.
  # The IP address must be valid on the machine where the program
  # runs, and the process must be privileged enough to listen
  # on the specified port (on Unix-like systems, superuser privileges
  # are usually required to listen on any port lower than 1024).
  # Only one listener may be running on any given address/port
  # combination. start_server will fail if the given address and port
  # are already listening on the machine, either because of a prior call
  # to start_server or some unrelated process running on the machine.
  # If start_server succeeds, the new network listener becomes active
  # immediately and starts accepting connections from remote peers,
  # and these connections generate callback events that are processed
  # by the code specified in the handler parameter to start_server.
  #
  # The optional handler which is passed to start_server is the key
  # to EventMachine's ability to handle particular network protocols.
  # The handler parameter passed to start_server must be a Ruby Module
  # that you must define. When the network server that is started by
  # start_server accepts a new connection, it instantiates a new
  # object of an anonymous class that is inherited from EventMachine::Connection,
  # <i>into which the methods from your handler have been mixed.</i>
  # Your handler module may redefine any of the methods in EventMachine::Connection
  # in order to implement the specific behavior of the network protocol.
  #
  # Callbacks invoked in response to network events <i>always</i> take place
  # within the execution context of the object derived from EventMachine::Connection
  # extended by your handler module. There is one object per connection, and
  # all of the callbacks invoked for a particular connection take the form
  # of instance methods called against the corresponding EventMachine::Connection
  # object. Therefore, you are free to define whatever instance variables you
  # wish, in order to contain the per-connection state required by the network protocol you are
  # implementing.
  #
  # start_server is often called inside the block passed to EventMachine::run,
  # but it can be called from any EventMachine callback. start_server will fail
  # unless the EventMachine event loop is currently running (which is why
  # it's often called in the block suppled to EventMachine::run).
  #
  # You may call start_server any number of times to start up network
  # listeners on different address/port combinations. The servers will
  # all run simultaneously. More interestingly, each individual call to start_server
  # can specify a different handler module and thus implement a different
  # network protocol from all the others.
  #
  # === Usage example
  # Here is an example of a server that counts lines of input from the remote
  # peer and sends back the total number of lines received, after each line.
  # Try the example with more than one client connection opened via telnet,
  # and you will see that the line count increments independently on each
  # of the client connections. Also very important to note, is that the
  # handler for the receive_data function, which our handler redefines, may
  # not assume that the data it receives observes any kind of message boundaries.
  # Also, to use this example, be sure to change the server and port parameters
  # to the start_server call to values appropriate for your environment.
  #
  #  require 'rubygems'
  #  require 'eventmachine'
  #
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
  #  EventMachine::run {
  #    host,port = "192.168.0.100", 8090
  #    EventMachine::start_server host, port, LineCounter
  #    puts "Now accepting connections on address #{host}, port #{port}..."
  #    EventMachine::add_periodic_timer( 10 ) { $stderr.write "*" }
  #  }
  #  
  #
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


  # Stop a TCP server socket that was started with EventMachine#start_server.
  #--
  # Requested by Kirk Haines. TODO, this isn't OOP enough. We ought somehow
  # to have #start_server return an object that has a close or a stop method on it.
  #
  def self.stop_server signature
    EventMachine::stop_tcp_server signature
  end

  # Start a Unix-domain server
  #
  # Note that this is an alias for EventMachine::start_server, which can be used to start both
  # TCP and Unix-domain servers
  def self.start_unix_domain_server filename, *args, &block
    start_server filename, *args, &block
  end

  # EventMachine#connect initiates a TCP connection to a remote
  # server and sets up event-handling for the connection.
  # You can call EventMachine#connect in the block supplied
  # to EventMachine#run or in any callback method.
  #
  # EventMachine#connect takes the IP address (or hostname) and
  # port of the remote server you want to connect to.
  # It also takes an optional handler Module which you must define, that
  # contains the callbacks that will be invoked by the event loop
  # on behalf of the connection.
  #
  # See the description of EventMachine#start_server for a discussion
  # of the handler Module. All of the details given in that description
  # apply for connections created with EventMachine#connect.
  #
  # === Usage Example
  #
  # Here's a program which connects to a web server, sends a naive
  # request, parses the HTTP header of the response, and then
  # (antisocially) ends the event loop, which automatically drops the connection
  # (and incidentally calls the connection's unbind method).
  # 
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
  #  EventMachine::run {
  #    EventMachine::connect "www.bayshorenetworks.com", 80, DumbHttpClient
  #  }
  #  puts "The event loop has ended"
  #  
  #
  # There are times when it's more convenient to define a protocol handler
  # as a Class rather than a Module. Here's how to do this:
  #
  #  class MyProtocolHandler < EventMachine::Connection
  #    def initialize *args
  #      super
  #      # whatever else you want to do here
  #    end
  #    
  #    #.......your other class code
  #  end
  #
  # If you do this, then an instance of your class will be instantiated to handle
  # every network connection created by your code or accepted by servers that you
  # create. If you redefine #post_init in your protocol-handler class, your
  # #post_init method will be called _inside_ the call to #super that you will
  # make in your #initialize method (if you provide one).
  #
  #--
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
  #
  def self.connect server, port=nil, handler=nil, *args, &blk
    bind_connect nil, nil, server, port, handler, *args, &blk
  end

  # EventMachine::bind_connect is like EventMachine::connect, but allows for a local address/port
  # to bind the connection to.
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

  # EventMachine::watch registers a given file descriptor or IO object with the eventloop. The
  # file descriptor will not be modified (it will remain blocking or non-blocking).
  #
  # The eventloop can be used to process readable and writable events on the file descriptor, using
  # EventMachine::Connection#notify_readable= and EventMachine::Connection#notify_writable=
  #
  # EventMachine::Connection#notify_readable? and EventMachine::Connection#notify_writable? can be used
  # to check what events are enabled on the connection.
  #
  # To detach the file descriptor, use EventMachine::Connection#detach
  #
  # === Usage Example
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
  #  EM.run{
  #    $sock = TCPSocket.new('site.com', 80)
  #    $sock.write("GET / HTTP/1.0\r\n\r\n")
  #    conn = EM.watch $sock, SimpleHttpClient
  #    conn.notify_readable = true
  #  }
  #
  #--
  # Thanks to Riham Aldakkak (eSpace Technologies) for the initial patch
  def EventMachine::watch io, handler=nil, *args, &blk
    attach_io io, true, handler, *args, &blk
  end

  # Attaches an IO object or file descriptor to the eventloop as a regular connection.
  # The file descriptor will be set as non-blocking, and EventMachine will process
  # receive_data and send_data events on it as it would for any other connection.
  #
  # To watch a fd instead, use EventMachine::watch, which will not alter the state of the socket
  # and fire notify_readable and notify_writable events instead.
  def EventMachine::attach io, handler=nil, *args, &blk
    attach_io io, false, handler, *args, &blk
  end

  def EventMachine::attach_io io, watch_mode, handler=nil, *args # :nodoc:
    klass = klass_from_handler(Connection, handler, *args)

    if !watch_mode and klass.public_instance_methods.any?{|m| [:notify_readable, :notify_writable].include? m.to_sym }
      raise ArgumentError, "notify_readable/writable with EM.attach is not supported. Use EM.watch(io){ |c| c.notify_readable = true }"
    end

    if io.respond_to?(:fileno)
      fd = defined?(JRuby) ? JRuby.runtime.getDescriptorByFileno(io.fileno).getChannel : io.fileno
    else
      fd = io
    end

    s = attach_fd fd, watch_mode
    c = klass.new s, *args

    c.instance_variable_set(:@io, io)
    c.instance_variable_set(:@fd, fd)

    @conns[s] = c
    block_given? and yield c
    c
  end


  # Connect to a given host/port and re-use the provided EventMachine::Connection instance
  #--
  # Observe, the test for already-connected FAILS if we call a reconnect inside post_init,
  # because we haven't set up the connection in @conns by that point.
  # RESIST THE TEMPTATION to "fix" this problem by redefining the behavior of post_init.
  #
  # Changed 22Nov06: if called on an already-connected handler, just return the
  # handler and do nothing more. Originally this condition raised an exception.
  # We may want to change it yet again and call the block, if any.
  #
  def self.reconnect server, port, handler # :nodoc:
    raise "invalid handler" unless handler.respond_to?(:connection_completed)
    #raise "still connected" if @conns.has_key?(handler.signature)
    return handler if @conns.has_key?(handler.signature)

    s = connect_server server, port
    handler.signature = s
    @conns[s] = handler
    block_given? and yield handler
    handler
  end


  # Make a connection to a Unix-domain socket. This is not implemented on Windows platforms.
  # The parameter socketname is a String which identifies the Unix-domain socket you want
  # to connect to. socketname is the name of a file on your local system, and in most cases
  # is a fully-qualified path name. Make sure that your process has enough local permissions
  # to open the Unix-domain socket.
  # See also the documentation for #connect. This method behaves like #connect
  # in all respects except for the fact that it connects to a local Unix-domain
  # socket rather than a TCP socket.
  #
  # Note that this method is simply an alias for #connect, which can connect to both TCP
  # and Unix-domain sockets
  #--
  # For making connections to Unix-domain sockets.
  # Eventually this has to get properly documented and unified with the TCP-connect methods.
  # Note how nearly identical this is to EventMachine#connect
  def self.connect_unix_domain socketname, *args, &blk
    connect socketname, *args, &blk
  end


  # EventMachine#open_datagram_socket is for support of UDP-based
  # protocols. Its usage is similar to that of EventMachine#start_server.
  # It takes three parameters: an IP address (which must be valid
  # on the machine which executes the method), a port number,
  # and an optional Module name which will handle the data.
  # This method will create a new UDP (datagram) socket and
  # bind it to the address and port that you specify.
  # The normal callbacks (see EventMachine#start_server) will
  # be called as events of interest occur on the newly-created
  # socket, but there are some differences in how they behave.
  #
  # Connection#receive_data will be called when a datagram packet
  # is received on the socket, but unlike TCP sockets, the message
  # boundaries of the received data will be respected. In other words,
  # if the remote peer sent you a datagram of a particular size,
  # you may rely on Connection#receive_data to give you the
  # exact data in the packet, with the original data length.
  # Also observe that Connection#receive_data may be called with a
  # <i>zero-length</i> data payload, since empty datagrams are permitted
  # in UDP.
  #
  # Connection#send_data is available with UDP packets as with TCP,
  # but there is an important difference. Because UDP communications
  # are <i>connectionless,</i> there is no implicit recipient for the packets you
  # send. Ordinarily you must specify the recipient for each packet you send.
  # However, EventMachine
  # provides for the typical pattern of receiving a UDP datagram
  # from a remote peer, performing some operation, and then sending
  # one or more packets in response to the same remote peer.
  # To support this model easily, just use Connection#send_data
  # in the code that you supply for Connection:receive_data.
  # EventMachine will
  # provide an implicit return address for any messages sent to
  # Connection#send_data within the context of a Connection#receive_data callback,
  # and your response will automatically go to the correct remote peer.
  # (TODO: Example-code needed!)
  #
  # Observe that the port number that you supply to EventMachine#open_datagram_socket
  # may be zero. In this case, EventMachine will create a UDP socket
  # that is bound to an <i>ephemeral</i> (not well-known) port.
  # This is not appropriate for servers that must publish a well-known
  # port to which remote peers may send datagrams. But it can be useful
  # for clients that send datagrams to other servers.
  # If you do this, you will receive any responses from the remote
  # servers through the normal Connection#receive_data callback.
  # Observe that you will probably have issues with firewalls blocking
  # the ephemeral port numbers, so this technique is most appropriate for LANs.
  # (TODO: Need an example!)
  #
  # If you wish to send datagrams to arbitrary remote peers (not
  # necessarily ones that have sent data to which you are responding),
  # then see Connection#send_datagram.
  #
  # DO NOT call send_data from a datagram socket
  # outside of a #receive_data method. Use #send_datagram. If you do use #send_data
  # outside of a #receive_data method, you'll get a confusing error
  # because there is no "peer," as #send_data requires. (Inside of #receive_data,
  # #send_data "fakes" the peer as described above.)
  #
  #--
  # Replaced the implementation on 01Oct06. Thanks to Tobias Gustafsson for pointing
  # out that this originally did not take a class but only a module.
  #
  def self.open_datagram_socket address, port, handler=nil, *args
    klass = klass_from_handler(Connection, handler, *args)
    s = open_udp_socket address, port.to_i
    c = klass.new s, *args
    @conns[s] = c
    block_given? and yield c
    c
  end


  # For advanced users. This function sets the default timer granularity, which by default is
  # slightly smaller than 100 milliseconds. Call this function to set a higher or lower granularity.
  # The function affects the behavior of #add_timer and #add_periodic_timer. Most applications
  # will not need to call this function.
  #
  # The argument is a number of milliseconds. Avoid setting the quantum to very low values because
  # that may reduce performance under some extreme conditions. We recommend that you not set a quantum
  # lower than 10.
  #
  # You may only call this function while an EventMachine loop is running (that is, after a call to
  # EventMachine#run and before a subsequent call to EventMachine#stop).
  #
  def self.set_quantum mills
    set_timer_quantum mills.to_i
  end

  # Sets the maximum number of timers and periodic timers that may be outstanding at any
  # given time. You only need to call #set_max_timers if you need more than the default
  # number of timers, which on most platforms is 1000.
  # Call this method before calling EventMachine#run.
  #
  def self.set_max_timers ct
    set_max_timer_count ct
  end

  # Gets the current maximum number of allowed timers
  #
  def self.get_max_timers
    get_max_timer_count
  end

  # Returns the total number of connections (file descriptors) currently held by the reactor.
  # Note that a tick must pass after the 'initiation' of a connection for this number to increment.
  # It's usually accurate, but don't rely on the exact precision of this number unless you really know EM internals.
  #
  # For example, $count will be 0 in this case:
  #
  #  EM.run {
  #    EM.connect("rubyeventmachine.com", 80)
  #    $count = EM.connection_count
  #  }
  #
  # In this example, $count will be 1 since the connection has been established in the next loop of the reactor.
  #
  #  EM.run {
  #    EM.connect("rubyeventmachine.com", 80)
  #    EM.next_tick {
  #      $count = EM.connection_count
  #    }
  #  }
  #
  def self.connection_count
    self.get_connection_count
  end

  #--
  # The is the responder for the loopback-signalled event.
  # It can be fired either by code running on a separate thread (EM#defer) or on
  # the main thread (EM#next_tick).
  # It will often happen that a next_tick handler will reschedule itself. We
  # consume a copy of the tick queue so that tick events scheduled by tick events
  # have to wait for the next pass through the reactor core.
  #
  def self.run_deferred_callbacks # :nodoc:
    until (@resultqueue ||= []).empty?
      result,cback = @resultqueue.pop
      cback.call result if cback
    end

    jobs = @next_tick_mutex.synchronize do
      jobs, @next_tick_queue = @next_tick_queue, []
      jobs
    end
    jobs.each { |j| j.call }
  end


  # #defer is for integrating blocking operations into EventMachine's control flow.
  # Call #defer with one or two blocks, as shown below (the second block is <i>optional</i>):
  #
  #  operation = proc {
  #    # perform a long-running operation here, such as a database query.
  #    "result" # as usual, the last expression evaluated in the block will be the return value.
  #  }
  #  callback = proc {|result|
  #    # do something with result here, such as send it back to a network client.
  #  }
  #
  #  EventMachine.defer( operation, callback )
  #
  # The action of #defer is to take the block specified in the first parameter (the "operation")
  # and schedule it for asynchronous execution on an internal thread pool maintained by EventMachine.
  # When the operation completes, it will pass the result computed by the block (if any)
  # back to the EventMachine reactor. Then, EventMachine calls the block specified in the
  # second parameter to #defer (the "callback"), as part of its normal, synchronous
  # event handling loop. The result computed by the operation block is passed as a parameter
  # to the callback. You may omit the callback parameter if you don't need to execute any code
  # after the operation completes.
  #
  # == Caveats
  # Note carefully that the code in your deferred operation will be executed on a separate
  # thread from the main EventMachine processing and all other Ruby threads that may exist in
  # your program. Also, multiple deferred operations may be running at once! Therefore, you
  # are responsible for ensuring that your operation code is threadsafe. [Need more explanation
  # and examples.]
  # Don't write a deferred operation that will block forever. If so, the current implementation will
  # not detect the problem, and the thread will never be returned to the pool. EventMachine limits
  # the number of threads in its pool, so if you do this enough times, your subsequent deferred
  # operations won't get a chance to run. [We might put in a timer to detect this problem.]
  #
  #--
  # OBSERVE that #next_tick hacks into this mechanism, so don't make any changes here
  # without syncing there.
  #
  # Running with $VERBOSE set to true gives a warning unless all ivars are defined when
  # they appear in rvalues. But we DON'T ever want to initialize @threadqueue unless we
  # need it, because the Ruby threads are so heavyweight. We end up with this bizarre
  # way of initializing @threadqueue because EventMachine is a Module, not a Class, and
  # has no constructor.
  #
  def self.defer op = nil, callback = nil, &blk
    unless @threadpool
      require 'thread'
      @threadpool = []
      @threadqueue = ::Queue.new
      @resultqueue = ::Queue.new
      spawn_threadpool
    end

    @threadqueue << [op||blk,callback]
  end

  def self.spawn_threadpool # :nodoc:
    until @threadpool.size == @threadpool_size.to_i
      thread = Thread.new do
        while true
          op, cback = *@threadqueue.pop
          result = op.call
          @resultqueue << [result, cback]
          EventMachine.signal_loopbreak
        end
      end
      @threadpool << thread
    end
  end

  class << self
    attr_reader :threadpool # :nodoc:

    # Size of the EventMachine.defer threadpool (defaults to 20)
    attr_accessor :threadpool_size
    EventMachine.threadpool_size = 20
  end

  # Schedules a proc for execution immediately after the next "turn" through the reactor
  # core. An advanced technique, this can be useful for improving memory management and/or
  # application responsiveness, especially when scheduling large amounts of data for
  # writing to a network connection. TODO, we need a FAQ entry on this subject.
  #
  # #next_tick takes either a single argument (which must be a Proc) or a block.
  #--
  # This works by adding to the @resultqueue that's used for #defer.
  # The general idea is that next_tick is used when we want to give the reactor a chance
  # to let other operations run, either to balance the load out more evenly, or to let
  # outbound network buffers drain, or both. So we probably do NOT want to block, and
  # we probably do NOT want to be spinning any threads. A program that uses next_tick
  # but not #defer shouldn't suffer the penalty of having Ruby threads running. They're
  # extremely expensive even if they're just sleeping.
  #
  def self.next_tick pr=nil, &block
    raise ArgumentError, "no proc or block given" unless ((pr && pr.respond_to?(:call)) or block)
    @next_tick_mutex.synchronize do
      (@next_tick_queue ||= []) << ( pr || block )
    end
    signal_loopbreak if reactor_running?
  end

  # A wrapper over the setuid system call. Particularly useful when opening a network
  # server on a privileged port because you can use this call to drop privileges
  # after opening the port. Also very useful after a call to #set_descriptor_table_size,
  # which generally requires that you start your process with root privileges.
  #
  # This method has no effective implementation on Windows or in the pure-Ruby
  # implementation of EventMachine.
  # Call #set_effective_user by passing it a string containing the effective name
  # of the user whose privilege-level your process should attain.
  # This method is intended for use in enforcing security requirements, consequently
  # it will throw a fatal error and end your program if it fails.
  #
  def self.set_effective_user username
    EventMachine::setuid_string username
  end


  # Sets the maximum number of file or socket descriptors that your process may open.
  # You can pass this method an integer specifying the new size of the descriptor table.
  # Returns the new descriptor-table size, which may be less than the number you
  # requested. If you call this method with no arguments, it will simply return
  # the current size of the descriptor table without attempting to change it.
  #
  # The new limit on open descriptors ONLY applies to sockets and other descriptors
  # that belong to EventMachine. It has NO EFFECT on the number of descriptors
  # you can create in ordinary Ruby code.
  #
  # Not available on all platforms. Increasing the number of descriptors beyond its
  # default limit usually requires superuser privileges. (See #set_effective_user
  # for a way to drop superuser privileges while your program is running.)
  #
  def self.set_descriptor_table_size n_descriptors=nil
    EventMachine::set_rlimit_nofile n_descriptors
  end



  # Run an external process. This does not currently work on Windows.
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
  #  EM.run{
  #    EM.popen("ruby -e' $stdout.sync = true; gets.to_i.times{ |i| puts i+1; sleep 1 } '", RubyCounter)
  #  }
  #
  # Also see EventMachine::DeferrableChildProcess and EventMachine.system
  #--
  # At this moment, it's only available on Unix.
  # Perhaps misnamed since the underlying function uses socketpair and is full-duplex.
  #
  def self.popen cmd, handler=nil, *args
    klass = klass_from_handler(Connection, handler, *args)
    w = Shellwords::shellwords( cmd )
    w.unshift( w.first ) if w.first
    s = invoke_popen( w )
    c = klass.new s, *args
    @conns[s] = c
    yield(c) if block_given?
    c
  end


  # Tells you whether the EventMachine reactor loop is currently running. Returns true or
  # false. Useful when writing libraries that want to run event-driven code, but may
  # be running in programs that are already event-driven. In such cases, if EventMachine#reactor_running?
  # returns false, your code can invoke EventMachine#run and run your application code inside
  # the block passed to that method. If EventMachine#reactor_running? returns true, just
  # execute your event-aware code.
  #
  # This method is necessary because calling EventMachine#run inside of another call to
  # EventMachine#run generates a fatal error.
  #
  def self.reactor_running?
    (@reactor_running || false)
  end


  # (Experimental)
  #
  #
  def self.open_keyboard handler=nil, *args
    klass = klass_from_handler(Connection, handler, *args)

    s = read_keyboard
    c = klass.new s, *args
    @conns[s] = c
    block_given? and yield c
    c
  end

  # EventMachine's file monitoring API. Currently supported are the following events
  # on individual files, using inotify on Linux systems, and kqueue for OSX/BSD:
  #
  # * File modified (written to)
  # * File moved/renamed
  # * File deleted
  #
  # EventMachine::watch_file takes a filename and a handler Module containing your custom callback methods.
  # This will setup the low level monitoring on the specified file, and create a new EventMachine::FileWatch
  # object with your Module mixed in. FileWatch is a subclass of EM::Connection, so callbacks on this object
  # work in the familiar way. The callbacks that will be fired by EventMachine are:
  #
  # * file_modified
  # * file_moved
  # * file_deleted
  #
  # You can access the filename being monitored from within this object using FileWatch#path.
  #
  # When a file is deleted, FileWatch#stop_watching will be called after your file_deleted callback, 
  # to clean up the underlying monitoring and remove EventMachine's reference to the now-useless FileWatch.
  # This will in turn call unbind, if you wish to use it.
  #
  # The corresponding system-level Errno will be raised when attempting to monitor non-existent files,
  # files with wrong permissions, or if an error occurs dealing with inotify/kqueue.
  #
  # === Usage example:
  #
  #  Make sure we have a file to monitor:
  #  $ echo "bar" > /tmp/foo
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
  #  EM.kqueue = true if EM.kqueue? # file watching requires kqueue on OSX
  #
  #  EM.run {
  #    EM.watch_file("/tmp/foo", Handler)
  #  }
  #
  #  $ echo "baz" >> /tmp/foo    =>    "/tmp/foo modified"
  #  $ mv /tmp/foo /tmp/oof      =>    "/tmp/foo moved"
  #  $ rm /tmp/oof               =>    "/tmp/foo deleted"
  #                              =>    "/tmp/foo monitoring ceased"
  #
  # Note that we have not implemented the ability to pick up on the new filename after a rename.
  # Calling #path will always return the filename you originally used.
  #
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

  # EventMachine's process monitoring API. Currently supported using kqueue for OSX/BSD.
  #
  # === Usage example:
  #
  #  module ProcessWatcher
  #    def process_exited
  #      put 'the forked child died!'
  #    end
  #  end
  #
  #  pid = fork{ sleep }
  #
  #  EM.run{
  #    EM.watch_process(pid, ProcessWatcher)
  #    EM.add_timer(1){ Process.kill('TERM', pid) }
  #  }
  #
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
  #  EM.error_handler{ |e|
  #    puts "Error raised during event loop: #{e.message}"
  #  }
  #
  def self.error_handler cb = nil, &blk
    if cb or blk
      @error_handler = cb || blk
    elsif instance_variable_defined? :@error_handler
      remove_instance_variable :@error_handler
    end
  end

  # enable_proxy allows for direct writing of incoming data back out to another descriptor, at the C++ level in the reactor.
  # This is especially useful for proxies where high performance is required. Propogating data from a server response
  # all the way up to Ruby, and then back down to the reactor to be sent back to the client, is often unnecessary and
  # incurs a significant performance decrease.
  #
  # The two arguments are Connections, 'from' and 'to'. 'from' is the connection whose inbound data you want
  # relayed back out. 'to' is the connection to write it to.
  #
  # Once you call this method, the 'from' connection will no longer get receive_data callbacks from the reactor,
  # except in the case that 'to' connection has already closed when attempting to write to it. You can see
  # in the example, that proxy_target_unbound will be called when this occurs. After that, further incoming
  # data will be passed into receive_data as normal.
  #
  # Note also that this feature supports different types of descriptors - TCP, UDP, and pipes. You can relay
  # data from one kind to another.
  #
  # Example:
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
  #        EM.connect("10.0.0.15", 80, ProxyConnection, self, data)
  #      end
  #    end
  #  end
  #
  #  EM.run {
  #    EM.start_server("127.0.0.1", 8080, ProxyServer)
  #  }
  def self.enable_proxy(from, to, bufsize=0)
    EM::start_proxy(from.signature, to.signature, bufsize)
  end

  # disable_proxy takes just one argument, a Connection that has proxying enabled via enable_proxy.
  # Calling this method will remove that functionality and your connection will begin receiving
  # data via receive_data again.
  def self.disable_proxy(from)
    EM::stop_proxy(from.signature)
  end

  # Retrieve the heartbeat interval. This is how often EventMachine will check for dead connections
  # that have had an InactivityTimeout set via Connection#set_comm_inactivity_timeout.
  # Default is 2 seconds.
  def self.heartbeat_interval
    EM::get_heartbeat_interval
  end

  # Set the heartbeat interval. This is how often EventMachine will check for dead connections
  # that have had an InactivityTimeout set via Connection#set_comm_inactivity_timeout.
  # Takes a Numeric number of seconds. Default is 2.
  def self.heartbeat_interval= (time)
    EM::set_heartbeat_interval time.to_f
  end

  private

  def self.event_callback conn_binding, opcode, data # :nodoc:
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
          c.unbind
        rescue
          @wrapped_exception = $!
          stop
        end
      elsif c = @acceptors.delete( conn_binding )
        # no-op
      else
        raise ConnectionNotBound, "recieved ConnectionUnbound for an unknown signature: #{conn_binding}"
      end
    elsif opcode == ConnectionAccepted
      accep,args,blk = @acceptors[conn_binding]
      raise NoHandlerForAcceptedConnection unless accep
      c = accep.new data, *args
      @conns[data] = c
      blk and blk.call(c)
      c # (needed?)
    elsif opcode == ConnectionCompleted
      c = @conns[conn_binding] or raise ConnectionNotBound, "received ConnectionCompleted for unknown signature: #{conn_binding}"
      c.connection_completed
    ##
    # The remaining code is a fallback for the pure ruby and java reactors.
    # In the C++ reactor, these events are handled in the C event_callback() in rubymain.cpp
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

  #--
  # The original event_callback below handled runtime errors in ruby and degraded performance significantly.
  # An optional C-based error handler is now available via EM::error_handler
  #
  # private
  # def EventMachine::original_event_callback conn_binding, opcode, data
  #   #
  #   # Added 03Oct07: Any code path that invokes user-written code must
  #   # wrap itself in a begin/rescue for RuntimeErrors, that calls the
  #   # user-overridable class method #handle_runtime_error.
  #   #
  #   if opcode == ConnectionData
  #     c = @conns[conn_binding] or raise ConnectionNotBound
  #     begin
  #       c.receive_data data
  #     rescue
  #       EventMachine.handle_runtime_error
  #     end
  #   elsif opcode == ConnectionUnbound
  #     if c = @conns.delete( conn_binding )
  #       begin
  #         c.unbind
  #       rescue
  #         EventMachine.handle_runtime_error
  #       end
  #     elsif c = @acceptors.delete( conn_binding )
  #       # no-op
  #     else
  #       raise ConnectionNotBound
  #     end
  #   elsif opcode == ConnectionAccepted
  #     accep,args,blk = @acceptors[conn_binding]
  #     raise NoHandlerForAcceptedConnection unless accep
  #     c = accep.new data, *args
  #     @conns[data] = c
  #     begin
  #       blk and blk.call(c)
  #     rescue
  #       EventMachine.handle_runtime_error
  #     end
  #     c # (needed?)
  #   elsif opcode == TimerFired
  #     t = @timers.delete( data ) or raise UnknownTimerFired
  #     begin
  #       t.call
  #     rescue
  #       EventMachine.handle_runtime_error
  #     end
  #   elsif opcode == ConnectionCompleted
  #     c = @conns[conn_binding] or raise ConnectionNotBound
  #     begin
  #       c.connection_completed
  #     rescue
  #       EventMachine.handle_runtime_error
  #     end
  #   elsif opcode == LoopbreakSignalled
  #     begin
  #     run_deferred_callbacks
  #     rescue
  #       EventMachine.handle_runtime_error
  #     end
  #   end
  # end
  #
  #
  # # Default handler for RuntimeErrors that are raised in user code.
  # # The default behavior is to re-raise the error, which ends your program.
  # # To override the default behavior, re-implement this method in your code.
  # # For example:
  # #
  # #  module EventMachine
  # #    def self.handle_runtime_error
  # #      $>.puts $!
  # #    end
  # #  end
  # #
  # #--
  # # We need to ensure that any code path which invokes user code rescues RuntimeError
  # # and calls this method. The obvious place to do that is in #event_callback,
  # # but, scurrilously, it turns out that we need to be finer grained that that.
  # # Periodic timers, in particular, wrap their invocations of user code inside
  # # procs that do other stuff we can't not do, like schedule the next invocation.
  # # This is a potential non-robustness, since we need to remember to hook in the
  # # error handler whenever and wherever we change how user code is invoked.
  # #
  # def EventMachine::handle_runtime_error
  #   @runtime_error_hook ? @runtime_error_hook.call : raise
  # end
  #
  # # Sets a handler for RuntimeErrors that are raised in user code.
  # # Pass a block with no parameters. You can also call this method without a block,
  # # which restores the default behavior (see #handle_runtime_error).
  # #
  # def EventMachine::set_runtime_error_hook &blk
  #   @runtime_error_hook = blk
  # end

  #--
  # This is a provisional implementation of a stream-oriented file access object.
  # We also experiment with wrapping up some better exception reporting.
  def self._open_file_for_writing filename, handler=nil # :nodoc:
    klass = klass_from_handler(Connection, handler)

    s = _write_file filename
    c = klass.new s
    @conns[s] = c
    block_given? and yield c
    c
  end

  private
  def self.klass_from_handler(klass = Connection, handler = nil, *args)
    klass = if handler and handler.is_a?(Class)
      raise ArgumentError, "must provide module or subclass of #{klass.name}" unless klass >= handler
      handler
    elsif handler
      Class.new(klass){ include handler }
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

# Save everyone some typing.
EM = EventMachine
EM::P = EventMachine::Protocols