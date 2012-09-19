module Thin
  module Backends
    # Backend to act as a TCP socket server.
    class TcpServer < Base
      # Address and port on which the server is listening for connections.
      attr_accessor :host, :port
      
      def initialize(host, port)
        @host = host
        @port = port
        super()
      end
      
      # Connect the server
      def connect
        @signature = EventMachine.start_server(@host, @port, Connection, &method(:initialize_connection))
      end
      
      # Stops the server
      def disconnect
        EventMachine.stop_server(@signature)
      end
            
      def to_s
        "#{@host}:#{@port}"
      end
    end
  end
end