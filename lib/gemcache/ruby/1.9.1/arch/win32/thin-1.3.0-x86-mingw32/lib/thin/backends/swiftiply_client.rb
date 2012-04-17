module Thin
  module Backends
    # Backend to act as a Swiftiply client (http://swiftiply.swiftcore.org).
    class SwiftiplyClient < Base
      attr_accessor :key
      
      attr_accessor :host, :port
      
      def initialize(host, port, options={})
        @host = host
        @port = port.to_i
        @key  = options[:swiftiply].to_s
        super()
      end

      # Connect the server
      def connect
        EventMachine.connect(@host, @port, SwiftiplyConnection, &method(:initialize_connection))
      end

      # Stops the server
      def disconnect
        EventMachine.stop
      end

      def to_s
        "#{@host}:#{@port} swiftiply"
      end
    end    
  end

  class SwiftiplyConnection < Connection
    def connection_completed
      send_data swiftiply_handshake(@backend.key)
    end
    
    def persistent?
      true
    end
    
    def unbind
      super
      EventMachine.add_timer(rand(2)) { reconnect(@backend.host, @backend.port) } if @backend.running?
    end
    
    protected
      def swiftiply_handshake(key)
        'swiftclient' << host_ip.collect { |x| sprintf('%02x', x.to_i)}.join << sprintf('%04x', @backend.port) << sprintf('%02x', key.length) << key
      end
      
      # For some reason Swiftiply request the current host
      def host_ip
        Socket.gethostbyname(@backend.host)[3].unpack('CCCC') rescue [0,0,0,0]
      end
  end
end