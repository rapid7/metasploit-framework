# -*- coding: binary -*-
#
# sf - Sept 2010 (original socks4a code)
# zeroSteiner - March 2018 (socks 5 update)

require 'bindata'
require 'thread'
require 'rex/logging'
require 'rex/socket'

module Rex
module Proto
module Proxy

#
# A Socks5 proxy server.
#
class Socks5

  #
  # A client connected to the Socks5 server.
  #
  class Client
    SOCKS_VERSION                   = 5

    AUTH_NONE                       = 0
    AUTH_GSSAPI                     = 1
    AUTH_CREDS                      = 2
    AUTH_NO_ACCEPTABLE_METHODS      = 255

    COMMAND_CONNECT                 = 1
    COMMAND_BIND                    = 2
    COMMAND_UDP_ASSOCIATE           = 3

    ADDRESS_TYPE_IPV4               = 1
    ADDRESS_TYPE_DOMAINNAME         = 3
    ADDRESS_TYPE_IPV6               = 4

    REQUEST_GRANTED                 = 90
    REQUEST_REJECT_FAILED           = 91
    REQUEST_REJECT_CONNECT          = 92
    REQUEST_REJECT_USERID           = 93

    HOST                            = 1
    PORT                            = 2

    class AuthRequestPacket < BinData::Record
      endian :big

      uint8  :version, :initial_value => SOCKS_VERSION
      uint8  :supported_methods_length
      array  :supported_methods, :type => :uint8, :initial_length => :supported_methods_length
    end

    class AuthResponsePacket < BinData::Record
      endian :big

      uint8  :version, :initial_value => SOCKS_VERSION
      uint8  :chosen_method, :initial_value => AUTH_NONE
    end

    module AddressMixin
      def address
        addr = address_array.to_ary.pack('C*')
        if address_type == ADDRESS_TYPE_IPV4 || address_type == ADDRESS_TYPE_IPV6
          addr = Rex::Socket.addr_ntoa(addr)
        end
        addr
      end

      def address=(value)
        if Rex::Socket.is_ipv4?(value)
          address_type.assign(ADDRESS_TYPE_IPV4)
          domainname_length.assign(0)
        elsif Rex::Socket.is_ipv6?(value)
          address_type.assign(ADDRESS_TYPE_IPV6)
          domainname_length.assign(0)
        else
          address_type.assign(ADDRESS_TYPE_DOMAINNAME)
          domainname_length.assign(value.length)
        end
        address_array.assign(Rex::Socket.addr_aton(value).unpack('C*'))
      end

      def address_length
        case address_type
          when ADDRESS_TYPE_IPV4
            4
          when ADDRESS_TYPE_DOMAINNAME
            domainname_length
          when ADDRESS_TYPE_IPV6
            16
          else
            0
        end
      end
    end

    class RequestPacket < BinData::Record
      include AddressMixin
      endian :big
      hide   :reserved, :domainname_length

      uint8  :version, :initial_value => SOCKS_VERSION
      uint8  :command
      uint8  :reserved
      uint8  :address_type
      uint8  :domainname_length, :onlyif => lambda { address_type == ADDRESS_TYPE_DOMAINNAME }
      array  :address_array, :type => :uint8, :initial_length => lambda { address_length }
      uint16 :port
    end

    class ResponsePacket < RequestPacket
    end

    #
    # Create a new client connected to the server.
    #
    def initialize( server, sock )
      @server        = server
      @lsock         = sock
      @rsock         = nil
      @client_thread = nil
      @mutex         = ::Mutex.new
    end

    # Start handling the client connection.
    #
    def start
      # create a thread to handle this client request so as to not block the socks5 server
      @client_thread = Rex::ThreadFactory.spawn("SOCKS5ProxyClient", false) do
        begin
          @server.add_client(self)
          # get the initial client request packet
          packet = AuthRequestPacket.read(@lsock.get_once)
          unless packet.supported_methods.include? AUTH_NONE
            raise "Invalid Socks5 request packet received (no supported authentication methods)."
          end
          @lsock.put(AuthResponsePacket.new.to_binary_s)
          STDERR.puts "Sent auth reply"

          packet = RequestPacket.read(@lsock.get_once)
          STDERR.puts "Received valid request"
          # handle the request
          handle_command(packet)

          # setup the two way relay for full duplex io
          @lsock.extend(Relay)
          @rsock.extend(Relay)
          # start the socket relays...
          @lsock.relay(self, @rsock)
          @rsock.relay(self, @lsock)
        rescue => exception
          STDERR.puts "Error during processing: #{$!}"
          STDERR.puts exception.backtrace
          wlog("Client.start - #{$!}")
          self.stop
        end
      end
    end

    def handle_command(request)
      response = nil
      begin
        case request.command
          when COMMAND_BIND
            response = handle_command_bind(request)
          when COMMAND_CONNECT
            response = handle_command_connect(request)
          when COMMAND_UDP_ASSOCIATE
            response = handle_command_udp_associate(request)
        end
        if response.nil?
          STDERR.puts "Command did not return a proper response object"
        else
          @lsock.put(response.to_binary_s)
          STDERR.puts "Set response to the client"
        end
      rescue => exception
        STDERR.puts "Error during processing: #{$!}"
        STDERR.puts exception.backtrace
        # send back failure to the client
        response         = ResponsePacket.new
        response.command = REQUEST_REJECT_FAILED
        @lsock.put(response.to_binary_s)
        # raise an exception to close this client connection
        raise "Failed to handle the clients request."
      end
    end

    def handle_command_bind(request)
      # create a server socket for this request
      params = {
        'LocalHost' => request.address,
        'LocalPort' => request.port
      }
      params['Context'] = @server.opts['Context'] if @server.opts.has_key?('Context')
      bsock = Rex::Socket::TcpServer.create(params)

      # send back the bind success to the client
      response              = ResponsePacket.new
      response.command      = REQUEST_GRANTED
      response.address      = bsock.localhost
      response.port         = bsock.localport
      @lsock.put(response.to_binary_s)

      # accept a client connection (2 minute timeout as per the socks4a spec)
      begin
        ::Timeout.timeout(120) do
          @rsock = bsock.accept
        end
      rescue ::Timeout::Error
        raise "Timeout reached on accept request."
      end

      # close the listening socket
      bsock.close

      response              = ResponsePacket.new
      response.version      = REPLY_VERSION
      response.command      = REQUEST_GRANTED
      response.address      = rpeer[HOST]
      response.port         = rpeer[PORT]
      response
    end

    def handle_command_connect(request)
      # perform the connection request
      params = {
        'PeerHost' => request.address,
        'PeerPort' => request.port,
      }
      params['Context'] = @server.opts['Context'] if @server.opts.has_key?('Context')
      @rsock = Rex::Socket::Tcp.create(params)

      response              = ResponsePacket.new
      response.command      = REQUEST_GRANTED
      response.address      = @rsock.peerhost
      response.port         = @rsock.peerport
      response
    end

    def handle_command_udp_associate(request)
      # create a udp socket for this request
      params = {
        'LocalHost' => request.address,
        'LocalPort' => request.port
      }
      params['Context'] = @server.opts['Context'] if @server.opts.has_key?('Context')
      @rsock = Rex::Socket::Udp.create(params)

      # send back the bind success to the client
      response              = ResponsePacket.new
      response.command      = REQUEST_GRANTED
      response.address      = @rsock.localhost
      response.port         = @rsock.localport
      response
    end

    #
    # Stop handling the client connection.
    #
    def stop
      @mutex.synchronize do
        unless @closed
          begin
            @lsock.close if @lsock
          rescue
          end

          begin
            @rsock.close if @rsock
          rescue
          end

          @client_thread.kill if @client_thread and @client_thread.alive?

          @server.remove_client(self)

          @closed = true
        end
      end
    end

  end

  #
  # Create a new Socks5 server.
  #
  def initialize(opts={})
    @opts          = { 'ServerHost' => '0.0.0.0', 'ServerPort' => 1080 }
    @opts          = @opts.merge(opts)
    @server        = nil
    @clients       = ::Array.new
    @running       = false
    @server_thread = nil
  end

  #
  # Check if the server is running.
  #
  def is_running?
    return @running
  end

  #
  # Start the Socks4a server.
  #
  def start
    begin
      # create the servers main socket (ignore the context here because we don't want a remote bind)
      @server = Rex::Socket::TcpServer.create('LocalHost' => @opts['ServerHost'], 'LocalPort' => @opts['ServerPort'])
      # signal we are now running
      @running = true
      # start the servers main thread to pick up new clients
      @server_thread = Rex::ThreadFactory.spawn("SOCKS5ProxyServer", false) do
        while @running
          begin
            # accept the client connection
            sock = @server.accept
            # and fire off a new client instance to handle it
            Client.new(self, sock).start
          rescue
            wlog("Socks5.start - server_thread - #{$!}")
          end
        end
      end
    rescue => exception
      STDERR.puts "Error during processing: #{$!}"
      STDERR.puts exception.backtrace
      wlog("Socks5.start - #{$!}")
      return false
    end
    return true
  end

  #
  # Block while the server is running.
  #
  def join
    @server_thread.join if @server_thread
  end

  #
  # Stop the Socks4a server.
  #
  def stop
    if @running
      # signal we are no longer running
      @running = false
      # stop any clients we have (create a new client array as client.stop will delete from @clients)
      clients = @clients.dup
      clients.each do | client |
        client.stop
      end
      # close the server socket
      @server.close if @server
      # if the server thread did not terminate gracefully, kill it.
      @server_thread.kill if @server_thread and @server_thread.alive?
    end
    return !@running
  end

  def add_client(client)
    @clients << client
  end

  def remove_client(client)
    @clients.delete(client)
  end

  attr_reader :opts

end

end; end; end

