# Class for implementing a proxy to filter/mangle MQTT packets.
class MQTT::Proxy
  # Address to bind listening socket to
  attr_reader :local_host

  # Port to bind listening socket to
  attr_reader :local_port

  # Address of upstream server to send packets upstream to
  attr_reader :server_host

  # Port of upstream server to send packets upstream to.
  attr_reader :server_port

  # Time in seconds before disconnecting an idle connection
  attr_reader :select_timeout

  # Ruby Logger object to send informational messages to
  attr_reader :logger

  # Create a new MQTT Proxy instance.
  #
  # Possible argument keys:
  #
  #  :local_host      Address to bind listening socket to.
  #  :local_port      Port to bind listening socket to.
  #  :server_host     Address of upstream server to send packets upstream to.
  #  :server_port     Port of upstream server to send packets upstream to.
  #  :select_timeout  Time in seconds before disconnecting a connection.
  #  :logger          Ruby Logger object to send informational messages to.
  #
  # NOTE: be careful not to connect to yourself!
  def initialize(args={})
    @local_host = args[:local_host] || '0.0.0.0'
    @local_port = args[:local_port] || MQTT::DEFAULT_PORT
    @server_host = args[:server_host]
    @server_port = args[:server_port] || 18830
    @select_timeout = args[:select_timeout] || 60

    # Setup a logger
    @logger = args[:logger]
    if @logger.nil?
      @logger = Logger.new(STDOUT)
      @logger.level = Logger::INFO
    end

    # Default is not to have any filters
    @client_filter = nil
    @server_filter = nil

    # Create TCP server socket
    @server = TCPServer.open(@local_host,@local_port)
    @logger.info "MQTT::Proxy listening on #{@local_host}:#{@local_port}"
  end

  # Set a filter Proc for packets coming from the client (to the server).
  def client_filter=(proc)
    @client_filter = proc
  end

  # Set a filter Proc for packets coming from the server (to the client).
  def server_filter=(proc)
    @server_filter = proc
  end

  # Start accepting connections and processing packets.
  def run
    loop do
      # Wait for a client to connect and then create a thread for it
      Thread.new(@server.accept) do |client_socket|
        logger.info "Accepted client: #{client_socket.peeraddr.join(':')}"
        server_socket = TCPSocket.new(@server_host,@server_port)
        begin
          process_packets(client_socket,server_socket)
        rescue Exception => exp
          logger.error exp.to_s
        end
        logger.info "Disconnected: #{client_socket.peeraddr.join(':')}"
        server_socket.close
        client_socket.close
      end
    end
  end

  private

  def process_packets(client_socket,server_socket)
    loop do
      # Wait for some data on either socket
      selected = IO.select([client_socket,server_socket], nil, nil, @select_timeout)
      if selected.nil?
        # Timeout
        raise "Timeout in select"
      else
        # Iterate through each of the sockets with data to read
        if selected[0].include?(client_socket)
          packet = MQTT::Packet.read(client_socket)
          logger.debug "client -> <#{packet.type_name}>"
          packet = @client_filter.call(packet) unless @client_filter.nil?
          unless packet.nil?
            server_socket.write(packet)
            logger.debug "<#{packet.type_name}> -> server"
          end
        elsif selected[0].include?(server_socket)
          packet = MQTT::Packet.read(server_socket)
          logger.debug "server -> <#{packet.type_name}>"
          packet = @server_filter.call(packet) unless @server_filter.nil?
          unless packet.nil?
            client_socket.write(packet)
            logger.debug "<#{packet.type_name}> -> client"
          end
        else
          logger.error "Problem with select: socket is neither server or client"
        end
      end
    end
  end

end
