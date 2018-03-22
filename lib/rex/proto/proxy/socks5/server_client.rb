# -*- coding: binary -*-

require 'bindata'
require 'rex/socket'
require 'rex/proto/proxy/socks5/packet'

module Rex
module Proto
module Proxy

#
# A client connected to the proxy server.
#
module Socks5
  #
  # A mixin for a socket to perform a relay to another socket.
  #
  module Relay
    #
    # Relay data coming in from relay_sock to this socket.
    #
    def relay( relay_client, relay_sock )
      @relay_client = relay_client
      @relay_sock   = relay_sock
      # start the relay thread (modified from Rex::IO::StreamAbstraction)
      @relay_thread = Rex::ThreadFactory.spawn("SOCKS4AProxyServerRelay", false) do
        loop do
          closed = false
          buf    = nil

          begin
            s = Rex::ThreadSafe.select( [ @relay_sock ], nil, nil, 0.2 )
            if( s == nil || s[0] == nil )
              next
            end
          rescue
            closed = true
          end

          if( closed == false )
            begin
              buf = @relay_sock.sysread( 32768 )
              closed = true if( buf == nil )
            rescue
              closed = true
            end
          end

          if( closed == false )
            total_sent   = 0
            total_length = buf.length
            while( total_sent < total_length )
              begin
                data = buf[total_sent, buf.length]
                sent = self.write( data )
                if( sent > 0 )
                  total_sent += sent
                end
              rescue
                closed = true
                break
              end
            end
          end

          if( closed )
            @relay_client.stop
            ::Thread.exit
          end
        end
      end
    end
  end

  #
  # A client connected to the Socks5 server.
  #
  class ServerClient
    AUTH_NONE                        = 0
    AUTH_GSSAPI                      = 1
    AUTH_CREDS                       = 2
    AUTH_NO_ACCEPTABLE_METHODS       = 255

    COMMAND_CONNECT                  = 1
    COMMAND_BIND                     = 2
    COMMAND_UDP_ASSOCIATE            = 3

    REPLY_SUCCEEDED                  = 0
    REPLY_GENERAL_FAILURE            = 1
    REPLY_NOT_ALLOWED                = 2
    REPLY_NET_UNREACHABLE            = 3
    REPLY_HOST_UNREACHABLE           = 4
    REPLY_CONNECTION_REFUSED         = 5
    REPLY_TTL_EXPIRED                = 6
    REPLY_CMD_NOT_SUPPORTED          = 7
    REPLY_ADDRESS_TYPE_NOT_SUPPORTED = 8

    #
    # Create a new client connected to the server.
    #
    def initialize(server, sock)
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
        response.command = REPLY_GENERAL_FAILURE
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
      response.command      = REPLY_SUCCEEDED
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
      response.command      = REPLY_SUCCEEDED
      response.address      = @rsock.peerhost
      response.port         = @rsock.peerport
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
      response.command      = REPLY_SUCCEEDED
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
      response.command      = REPLY_SUCCEEDED
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
end
end
end
end
