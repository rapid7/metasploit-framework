require 'socket'
require 'forwardable'

begin
require 'ruby-debug'

# Experimental!

class SporkDebugger
  DEFAULT_PORT = 10_123
  HOST = '127.0.0.1'

  extend Forwardable
  def_delegators :state, *[:prepare_debugger, :initialize]
  attr_reader :state

  class << self
    attr_reader :instance
    def run
      @instance ||= new
    end
  end

  def initialize
    @state = SporkDebugger::PreloadState.new
    Spork.send(:each_run_procs).unshift(lambda do
      @state = @state.transition_to_each_run_state
    end)
  end

  module NetworkHelpers
    def find_port(starting_with)
      port = starting_with
      begin
        server = TCPServer.new(HOST, port)
        server.close
      rescue Errno::EADDRINUSE
        port += 1
        retry
      end

      port
    end
  end

  class PreloadState
    include NetworkHelpers
    def initialize
      Spork.each_run { install_hook }
      listen_for_connection_signals
    end

    def finish
      @tcp_service.close; @tcp_service = nil;
    end

    def transition_to_each_run_state
      finish
      SporkDebugger::EachRunState.new(@port)
    end

    protected
      def install_hook
        Kernel.class_eval do
          alias :debugger_without_spork_hook :debugger
          def debugger(steps = 1)
            SporkDebugger.instance.prepare_debugger
            debugger_without_spork_hook
          end
        end
      end

      def listen_for_connection_signals
        @port = SporkDebugger::DEFAULT_PORT
        begin
          @tcp_service = TCPServer.new(SporkDebugger::HOST, @port)
        rescue Errno::EADDRINUSE
          @port += 1
          retry
        end
        Thread.new { main_loop }
      end

      def main_loop
        while @tcp_service do
          socket = @tcp_service.accept
          port = Marshal.load(socket)
          Marshal.dump(true, socket)
          connect_rdebug_client(port)
          socket.close
        end
      rescue => e
        puts "error: #{e.class} - #{e}"
      end

      def connect_rdebug_client(port = Debugger::PORT)
        puts "\n\n - Debug Session Started - \n\n\n"
        begin
          Debugger.start_client(SporkDebugger::HOST, port)
        rescue Errno::EPIPE, Errno::ECONNRESET, Errno::ECONNREFUSED
        end
        puts "\n\n - Debug Session Terminated - \n\n\n"
      end
  end

  class EachRunState
    include NetworkHelpers
    def initialize(connection_request_port)
      @connection_request_port = connection_request_port
    end

    def prepare_debugger
      return if @debugger_prepared
      @debugger_prepared = true
      port, cport = start_rdebug_server
      signal_spork_server_to_connect_to_rdebug_server(port)
      wait_for_connection
      puts "\n\n - breakpoint - see your spork server for the debug terminal - \n\n"
    end

    def signal_spork_server_to_connect_to_rdebug_server(rdebug_server_port)
      socket = TCPSocket.new(SporkDebugger::HOST, @connection_request_port)
      Marshal.dump(rdebug_server_port, socket)
      response = Marshal.load(socket)
      socket.close
    end

    def start_rdebug_server
      Debugger.stop if Debugger.started?
      port = find_port(Debugger::PORT)
      cport = find_port(port + 1)
      Debugger.start_remote(SporkDebugger::HOST, [port, cport]) do
        Debugger.run_init_script(StringIO.new)
      end
      Debugger.start
      [port, cport]
    end

    protected
      def wait_for_connection
        while Debugger.handler.interface.nil?; sleep 0.10; end
      end
  end
end

Spork.prefork { SporkDebugger.run } if Spork.using_spork?

rescue LoadError
  raise LoadError, "Your project has loaded spork/ext/ruby-debug, which relies on the ruby-debug gem. It appears that ruby-debug is not installed. Please install it."
end
