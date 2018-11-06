module Thin
  module Backends
    # A Backend connects the server to the client. It handles:
    # * connection/disconnection to the server
    # * initialization of the connections
    # * monitoring of the active connections.
    #
    # == Implementing your own backend
    # You can create your own minimal backend by inheriting this class and
    # defining the +connect+ and +disconnect+ method.
    # If your backend is not based on EventMachine you also need to redefine
    # the +start+, +stop+, <tt>stop!</tt> and +config+ methods.
    class Base
      # Server serving the connections throught the backend
      attr_accessor :server
      
      # Maximum time for incoming data to arrive
      attr_accessor :timeout
      
      # Maximum number of file or socket descriptors that the server may open.
      attr_accessor :maximum_connections
      
      # Maximum number of connections that can be persistent
      attr_accessor :maximum_persistent_connections

      #allows setting of the eventmachine threadpool size
      attr_reader :threadpool_size
      def threadpool_size=(size)
        @threadpool_size = size
        EventMachine.threadpool_size = size
      end

      # Allow using threads in the backend.
      attr_writer :threaded
      def threaded?; @threaded end
            
      # Allow using SSL in the backend.
      attr_writer :ssl, :ssl_options
      def ssl?; @ssl end
      
      # Number of persistent connections currently opened
      attr_accessor :persistent_connection_count
      
      # Disable the use of epoll under Linux
      attr_accessor :no_epoll
      
      def initialize
        @connections                    = {}
        @timeout                        = Server::DEFAULT_TIMEOUT
        @persistent_connection_count    = 0
        @maximum_connections            = Server::DEFAULT_MAXIMUM_CONNECTIONS
        @maximum_persistent_connections = Server::DEFAULT_MAXIMUM_PERSISTENT_CONNECTIONS
        @no_epoll                       = false
        @ssl                            = nil
        @threaded                       = nil
        @started_reactor                = false
      end
      
      # Start the backend and connect it.
      def start
        @stopping = false
        starter   = proc do
          connect
          yield if block_given?
          @running = true
        end
        
        # Allow for early run up of eventmachine.
        if EventMachine.reactor_running?
          starter.call
        else
          @started_reactor = true
          EventMachine.run(&starter)
        end
      end
      
      # Stop of the backend from accepting new connections.
      def stop
        @running  = false
        @stopping = true
        
        # Do not accept anymore connection
        disconnect
        # Close idle persistent connections
        @connections.each_value { |connection| connection.close_connection if connection.idle? }
        stop! if @connections.empty?
      end
      
      # Force stop of the backend NOW, too bad for the current connections.
      def stop!
        @running  = false
        @stopping = false
        
        EventMachine.stop if @started_reactor && EventMachine.reactor_running?
        @connections.each_value { |connection| connection.close_connection }
        close
      end
      
      # Configure the backend. This method will be called before droping superuser privileges,
      # so you can do crazy stuff that require godlike powers here.
      def config
        # See http://rubyeventmachine.com/pub/rdoc/files/EPOLL.html
        EventMachine.epoll unless @no_epoll
        
        # Set the maximum number of socket descriptors that the server may open.
        # The process needs to have required privilege to set it higher the 1024 on
        # some systems.
        @maximum_connections = EventMachine.set_descriptor_table_size(@maximum_connections) unless Thin.win?
      end
      
      # Free up resources used by the backend.
      def close
      end
      
      # Returns +true+ if the backend is connected and running.
      def running?
        @running
      end

      def started_reactor?
        @started_reactor
      end
            
      # Called by a connection when it's unbinded.
      def connection_finished(connection)
        @persistent_connection_count -= 1 if connection.can_persist?
        @connections.delete(connection.__id__)
        
        # Finalize gracefull stop if there's no more active connection.
        stop! if @stopping && @connections.empty?
      end
      
      # Returns +true+ if no active connection.
      def empty?
        @connections.empty?
      end
      
      # Number of active connections.
      def size
        @connections.size
      end
      
      protected
        # Initialize a new connection to a client.
        def initialize_connection(connection)
          connection.backend                 = self
          connection.app                     = @server.app
          connection.comm_inactivity_timeout = @timeout
          connection.threaded                = @threaded
          
          if @ssl
            connection.start_tls(@ssl_options)
          end

          # We control the number of persistent connections by keeping
          # a count of the total one allowed yet.
          if @persistent_connection_count < @maximum_persistent_connections
            connection.can_persist!
            @persistent_connection_count += 1
          end

          @connections[connection.__id__] = connection
        end
      
    end
  end
end
