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
  module TcpRelay
    #
    # TcpRelay data coming in from relay_sock to this socket.
    #
    def relay(relay_client, relay_sock)
      @relay_client = relay_client
      @relay_sock   = relay_sock
      # start the relay thread (modified from Rex::IO::StreamAbstraction)
      @relay_thread = Rex::ThreadFactory.spawn("SOCKS5ProxyServerTcpRelay", false) do
        loop do
          closed = false
          buf    = nil

          begin
            s = Rex::ThreadSafe.select([@relay_sock], nil, nil, 0.2)
            next if s.nil? || s[0].nil?
          rescue
            closed = true
          end

          unless closed
            begin
              buf = @relay_sock.sysread( 32768 )
              closed = buf.nil?
            rescue
              closed = true
            end
          end

          unless closed
            total_sent   = 0
            total_length = buf.length
            while total_sent < total_length
              begin
                data = buf[total_sent, buf.length]
                sent = self.write(data)
                total_sent += sent if sent > 0
              rescue
                closed = true
                break
              end
            end
          end

          if closed
            @relay_client.stop
            ::Thread.exit
          end
        end
      end
    end
  end

  #
  # A client connected to the SOCKS5 server.
  #
  class ServerClient
    AUTH_NONE                        = 0
    AUTH_GSSAPI                      = 1
    AUTH_CREDS                       = 2
    AUTH_NO_ACCEPTABLE_METHODS       = 255

    AUTH_PROTOCOL_VERSION            = 1
    AUTH_RESULT_SUCCESS              = 0
    AUTH_RESULT_FAILURE              = 1

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

    HOST = 1
    PORT = 2

    #
    # Create a new client connected to the server.
    #
    def initialize(server, sock, opts={})
      @server        = server
      @lsock         = sock
      @opts          = opts
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
          handle_authentication

          # handle the request
          handle_command
        rescue => exception
          # respond with a general failure to the client
          response         = ResponsePacket.new
          response.command = REPLY_GENERAL_FAILURE
          @lsock.put(response.to_binary_s)

          wlog("Client.start - #{$!}")
          self.stop
        end
      end
    end

    def handle_authentication
      request = AuthRequestPacket.read(@lsock.get_once)
      if @opts['ServerUsername'].nil? && @opts['ServerPassword'].nil?
        handle_authentication_none(request)
      else
        handle_authentication_creds(request)
      end
    end

    def handle_authentication_creds(request)
      unless request.supported_methods.include? AUTH_CREDS
        raise "Invalid SOCKS5 request packet received (no supported authentication methods)."
      end
      response = AuthResponsePacket.new
      response.chosen_method = AUTH_CREDS
      @lsock.put(response.to_binary_s)

      version = @lsock.read(1)
      raise "Invalid SOCKS5 authentication packet received." unless version.unpack('C').first == 0x01

      username_length = @lsock.read(1).unpack('C').first
      username        = @lsock.read(username_length)

      password_length = @lsock.read(1).unpack('C').first
      password        = @lsock.read(password_length)

      #  +-----+--------+
      #  | VER | STATUS |
      #  +-----+--------+  VERSION: 0x01
      #  | 1   | 1      |  STATUS:  0x00=SUCCESS, otherwise FAILURE
      #  +-----+--------+
      if username == @opts['ServerUsername'] && password == @opts['ServerPassword']
        raw = [ AUTH_PROTOCOL_VERSION, AUTH_RESULT_SUCCESS ].pack ('CC')
        ilog("SOCKS5: Successfully authenticated")
        @lsock.put(raw)
      else
        raw = [ AUTH_PROTOCOL_VERSION, AUTH_RESULT_FAILURE ].pack ('CC')
        @lsock.put(raw)
        raise "Invalid SOCKS5 credentials provided"
      end
    end

    def handle_authentication_none(request)
      unless request.supported_methods.include? AUTH_NONE
        raise "Invalid SOCKS5 request packet received (no supported authentication methods)."
      end
      response = AuthResponsePacket.new
      response.chosen_method = AUTH_NONE
      @lsock.put(response.to_binary_s)
    end

    def handle_command
      request = RequestPacket.read(@lsock.get_once)
      response = nil
      case request.command
        when COMMAND_BIND
          response = handle_command_bind(request)
        when COMMAND_CONNECT
          response = handle_command_connect(request)
        when COMMAND_UDP_ASSOCIATE
          response = handle_command_udp_associate(request)
      end
      @lsock.put(response.to_binary_s) unless response.nil?
    end

    def handle_command_bind(request)
      # create a server socket for this request
      params = {
        'LocalHost' => request.address_type == Address::ADDRESS_TYPE_IPV6 ? '::' : '0.0.0.0',
        'LocalPort' => 0,
      }
      params['Context'] = @server.opts['Context'] if @server.opts.has_key?('Context')
      bsock = Rex::Socket::TcpServer.create(params)

      # send back the bind success to the client
      response              = ResponsePacket.new
      response.command      = REPLY_SUCCEEDED
      response.address      = bsock.getlocalname[HOST]
      response.port         = bsock.getlocalname[PORT]
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

      setup_tcp_relay
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

      setup_tcp_relay
      response              = ResponsePacket.new
      response.command      = REPLY_SUCCEEDED
      response.address      = @rsock.getlocalname[HOST]
      response.port         = @rsock.getlocalname[PORT]
      response
    end

    def handle_command_udp_associate(request)
      response              = ResponsePacket.new
      response.command      = REPLY_CMD_NOT_SUPPORTED
      response
    end

    #
    # Setup the TcpRelay between lsock and rsock.
    #
    def setup_tcp_relay
      # setup the two way relay for full duplex io
      @lsock.extend(TcpRelay)
      @rsock.extend(TcpRelay)
      # start the socket relays...
      @lsock.relay(self, @rsock)
      @rsock.relay(self, @lsock)
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
