
# -*- coding: binary -*-
#
# sf - Sept 2010
# surefire - May 2018
#
# TODO: Add support for required SOCKS username+password authentication
# TODO: Support multiple connection requests within a single session
#
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

    # COMMON HEADER FIELDS

    RESERVED                                = 0

    # ADDRESS TYPES

    ADDRESS_TYPE_IPV4                       = 1
    ADDRESS_TYPE_DOMAINNAME                 = 3
    ADDRESS_TYPE_IPV6                       = 4

    # AUTHENTICATION TYPES
    AUTH_PROTOCOL_VERSION                   = 0x01

    AUTH_METHOD_TYPE_NONE                   = 0x00
    AUTH_METHOD_TYPE_USER_PASS              = 0x02

    AUTH_METHODS_REJECTED                   = 0xFF

    AUTH_SUCCESS                            = 0x00
    AUTH_FAILURE                            = 0x01

    # REQUEST HEADER FIELDS

    REQUEST_VERSION                         = 5

    REQUEST_AUTH_METHOD_COUNT               = 1

    REQUEST_COMMAND_CONNECT                 = 1
    REQUEST_COMMAND_BIND                    = 2
    REQUEST_COMMAND_UDP_ASSOCIATE           = 3     # TODO: support UDP associate

    # RESPONSE HEADER FIELDS

    REPLY_VERSION                           = 5
    REPLY_FIELD_SUCCEEDED                   = 0
    REPLY_FIELD_SOCKS_SERVER_FAILURE        = 1
    REPLY_FIELD_NOT_ALLOWED_BY_RULESET      = 2
    REPLY_FIELD_NETWORK_UNREACHABLE         = 3
    REPLY_FIELD_HOST_UNREACHABLE            = 4
    REPLY_FIELD_CONNECTION_REFUSED          = 5
    REPLY_FIELD_TTL_EXPIRED                 = 6
    REPLY_FIELD_COMMAND_NOT_SUPPORTED       = 7
    REPLY_FIELD_ADDRESS_TYPE_NOT_SUPPORTED  = 8

    # RPEER INDEXES

    HOST                                    = 1
    PORT                                    = 2

    class Response

      def initialize( sock )
        @version    = REQUEST_VERSION
        @command    = nil
        @reserved   = RESERVED
        @atyp       = nil
        @dest_port  = 0
        @dest_ip    = '0.0.0.0'
        @sock       = sock
      end

      # convert IPv6 hex-encoded, colon-delimited string (0000:1111:...) into a 128-bit address
      def ipv6_atoi(ip)
        raw = ""
        ip.scan(/....:/).each do |quad|
          raw += quad[0,2].hex.chr
          raw += quad[2,4].hex.chr
        end
        return raw
      end

      # Pack a packet into raw bytes for transmitting on the wire.
      def to_r
        begin

          if @atyp == ADDRESS_TYPE_DOMAINNAME
            if @dest_ip.include? '.'        # stupid check for IPv4 addresses
              @atyp = ADDRESS_TYPE_IPV4
            elsif @dest_ip.include? ':'     # stupid check for IPv4 addresses
              @atyp = ADDRESS_TYPE_IPV6
            else
              raise "Malformed dest_ip while sending SOCKS5 response packet"
            end
          end

          if @atyp == ADDRESS_TYPE_IPV4
            raw = [ @version, @command, @reserved, @atyp, Rex::Socket.addr_atoi(@dest_ip), @dest_port ].pack( 'CCCCNn' )
          elsif @atyp == ADDRESS_TYPE_IPV6
            raw = [ @version, @command, @reserved, @atyp ].pack ( 'CCCC')
            raw += ipv6_atoi(@dest_ip)
            raw += [ @dest_port ].pack( 'n' )
          else
            raise "Invalid address type field encountered while sending SOCKS5 response packet"
          end

          return raw

        rescue TypeError
          raise "Invalid field conversion while sending SOCKS5 response packet"
        end
      end

      def send
        @sock.put(self.to_r)
      end

      attr_writer :version, :command, :dest_port, :dest_ip, :hostname, :atyp
    end

    class Request

      def initialize( sock )
        @version    = REQUEST_VERSION
        @command    = nil
        @atyp       = nil
        @dest_port  = nil
        @dest_ip    = nil
        @sock       = sock
        @username   = nil
        @password   = nil
        @serverAuthMethods = [ 0x00 ]
      end

      def requireAuthentication( username, password )
        @username = username
        @password = password
        @serverAuthMethods = [ AUTH_METHOD_TYPE_USER_PASS ]
      end

      # The first packet sent by the client is a session request
      # +----+----------+----------+
      # |VER | NMETHODS | METHODS  |
      # +----+----------+----------+
      # | 1  |    1     | 1 to 255 |      METHOD (\x00) = NO AUTHENTICATION REQUIRED
      # +----+----------+----------+
      def parseIncomingSession()
        raw = ''

        version = @sock.read( 1 )
        raise "Invalid Socks5 request packet received." if not
          ( version.unpack( 'C' ).first == REQUEST_VERSION )

        nMethods = @sock.read( 1 ).unpack( 'C' ).first

        unpackFormatStr = 'C' + nMethods.to_s                                     # IS THIS REALLY WHAT I'M DOING?!
        clientAuthMethods = @sock.read( nMethods ).unpack( unpackFormatStr )
        authMethods = ( clientAuthMethods & @serverAuthMethods )

        if ( authMethods.empty? )
          raw = [ REQUEST_VERSION, AUTH_METHODS_REJECTED ].pack ( 'CC' )
          @sock.put( raw )
          raise "No matching authentication methods agreed upon in session request"
        else
          raw = [REQUEST_VERSION, authMethods[0]].pack ( 'CC' )
          @sock.put( raw )

          parseIncomingCredentials() if authMethods[0] == AUTH_METHOD_TYPE_USER_PASS 
        end
      end

      def parseIncomingCredentials()
        # Based on RFC1929: https://tools.ietf.org/html/rfc1929
        #   +----+------+----------+------+----------+
        #   |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
        #   +----+------+----------+------+----------+
        #   | 1  |  1   | 1 to 255 |  1   | 1 to 255 |  VERSION: 0x01
        #   +----+------+----------+------+----------+

        version = @sock.read( 1 )
        raise "Invalid SOCKS5 authentication packet received." if not
          ( version.unpack( 'C' ).first == 0x01 )

        usernameLength = @sock.read( 1 ).unpack( 'C' ).first
        username       = @sock.read( usernameLength )

        passwordLength = @sock.read( 1 ).unpack( 'C' ).first
        password       = @sock.read( passwordLength )

        #   +----+--------+
        #   |VER | STATUS |
        #   +----+--------+  VERSION: 0x01
        #   | 1  |   1    |  STATUS:  0x00=SUCCESS, otherwise FAILURE
        #   +----+--------+

        if (username == @username && password == @password)
          raw = [ AUTH_PROTOCOL_VERSION, AUTH_SUCCESS ].pack ( 'CC' )
          ilog("SOCKS5: Successfully authenticated")
          @sock.put( raw )
          return true
        else 
          raw = [ AUTH_PROTOCOL_VERSION, AUTH_FAILURE ].pack ( 'CC' )
          @sock.put( raw )
          raise "Invalid SOCKS5 credentials provided"
        end

      end

      def parseIncomingConnectionRequest()
        raw = @sock.read ( 262 )  # MAX LENGTH OF REQUEST WITH 256 BYTE HOSTNAME

        # fail if the incoming request is less than 8 bytes (malformed)
        raise "Client closed connection while expecting SOCKS connection request" if( raw == nil )
        raise "Client sent malformed packet expecting SOCKS connection request" if( raw.length < 8 )

        # Per RFC1928, the lengths of the SOCKS5 request header are:
        # +----+-----+-------+------+----------+----------+
        # |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        # +----+-----+-------+------+----------+----------+
        # | 1  |  1  | X'00' |  1   | Variable |    2     |
        # +----+-----+-------+------+----------+----------+

        @version   = raw[0..0].unpack( 'C' ).first
        # fail if the incoming request is an unsupported version (not '0x05')
        raise "Invalid SOCKS version received from client" if( @version != REQUEST_VERSION )

        @command   = raw[1..1].unpack( 'C' ).first
        # fail if the incoming request is an unsupported command (currently only CONNECT)
        raise "Invalid SOCKS proxy command received from client" if ( @command != REQUEST_COMMAND_CONNECT )

        # "address type of following address"
        @atyp      = raw[3..3].unpack( 'C' ).first

        if (@atyp == ADDRESS_TYPE_IPV4)
          # "the address is a version-4 IP address, with a length of 4 octets"
          addressLen = 4
          addressEnd = 3 + addressLen

          hostname   = nil
          @dest_ip  = Rex::Socket.addr_itoa( raw[4..7].unpack('N').first )
        elsif (@atyp == ADDRESS_TYPE_IPV6)
          # "the address is a version-6 IP address, with a length of 16 octets"
          addressLen = 16
          addressEnd = 3 + addressLen

          hostname   = nil
          @dest_ip  = raw[4..19].unpack( 'H4H4H4H4H4H4H4H4' ).join(':')  # Workaround because Rex::Socket.addr_itoa hurts too much
        elsif (@atyp == ADDRESS_TYPE_DOMAINNAME)
          # "the address field contains a fully-qualified domain name.  The first
          # octet of the address field contains the number of octets of name that
          # follow, there is no terminating NUL octet."

          addressLen   = raw[4..4].unpack( 'C' ).first
          addressStart = 5
          addressEnd   = 4+addressLen

          @hostname    = raw[addressStart..addressEnd]

          @dest_ip    = self.resolve( @hostname )
          ilog("SOCKS5: Resolved '#{@hostname}' to #{@dest_ip.to_s}")

          # fail if we couldnt resolve the hostname
          if( not @dest_ip )
            wlog("SOCKS5: Failed to resolve '#{@hostname}'...")
          end

        else
          raise 'Invalid address type requested in connection request'
        end

        @dest_port = raw[addressEnd+1 .. addressEnd+3].unpack('n').first

        return true
      end

      def is_connect?
        @command == REQUEST_COMMAND_CONNECT ? true : false
      end

      def is_bind?
        @command == REQUEST_COMMAND_BIND ? true : false
      end

      attr_reader :version, :command, :dest_port, :dest_ip, :hostname, :atyp

      protected

      # Resolve the given hostname into a dotted IP address.
      def resolve( hostname )
        if( not hostname.empty? )
          begin
            return Rex::Socket.addr_itoa( Rex::Socket.gethostbyname( hostname )[3].unpack( 'N' ).first )
          rescue ::SocketError
            return nil
          end
        end
        return nil
      end
    end

    # A mixin for a socket to perform a relay to another socket.
    module Relay

      #
      # Relay data coming in from relay_sock to this socket.
      #
      def relay( relay_client, relay_sock )
        @relay_client = relay_client
        @relay_sock   = relay_sock
        # start the relay thread (modified from Rex::IO::StreamAbstraction)
        @relay_thread = Rex::ThreadFactory.spawn("SOCKS5ProxyServerRelay", false) do
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

    # Create a new client connected to the server.
    def initialize( server, sock, opts )
      @username      = opts['USERNAME']
      @password      = opts['PASSWORD']
      @server        = server
      @lsock         = sock
      @rsock         = nil
      @client_thread = nil
      @mutex         = ::Mutex.new
    end

    # Start handling the client connection.
    def start
      # create a thread to handle this client request so as to not block the socks5 server
      @client_thread = Rex::ThreadFactory.spawn("SOCKS5ProxyClient", false) do
        begin
          @server.add_client( self )

          # get the initial client request packet
          request = Request.new ( @lsock )
          if not (@username.nil? or @password.nil?)
            request.requireAuthentication( @username, @password )
          end

          # negotiate authentication
          request.parseIncomingSession()

          # negotiate authentication
          request.parseIncomingConnectionRequest()

          # handle the request
          begin
            # handle CONNECT requests
            if( request.is_connect? )
              # perform the connection request
              params = {
                'PeerHost' => request.dest_ip,
                'PeerPort' => request.dest_port,
              }
              params['Context'] = @server.opts['Context'] if @server.opts.has_key?('Context')

              @rsock = Rex::Socket::Tcp.create( params )
              # and send back success to the client
              response           = Response.new ( @lsock )
              response.version   = REPLY_VERSION
              response.command   = REPLY_FIELD_SUCCEEDED
              response.atyp      = request.atyp
              response.hostname  = request.hostname
              response.dest_port = request.dest_port
              response.dest_ip   = request.dest_ip
              ilog("SOCKS5: request accepted to " + request.dest_ip.to_s + request.dest_port.to_s)
              response.send()
            # handle BIND requests
            elsif( request.is_bind? )                       # TODO: Test the BIND code with SOCKS5 (this is the old SOCKS4 code)
              # create a server socket for this request
              params = {
                'LocalHost' => '0.0.0.0',
                'LocalPort' => 0,
              }
              params['Context'] = @server.opts['Context'] if @server.opts.has_key?('Context')
              bsock = Rex::Socket::TcpServer.create( params )
              # send back the bind success to the client
              response           = Response.new ( @lsock )
              response.version   = REPLY_VERSION
              response.command   = REPLY_FIELD_SUCCEEDED
              response.atyp      = request.atyp
              response.hostname  = request.hostname
              response.dest_ip   = '0.0.0.0'
              response.dest_port = bsock.getlocalname()[PORT]
              response.send()
              ilog("SOCKS5: BIND request accepted to " + request.dest_ip.to_s + request.dest_port.to_s)
              # accept a client connection (2 minute timeout as per spec)
              begin
                ::Timeout.timeout( 120 ) do
                  @rsock = bsock.accept
                end
              rescue ::Timeout::Error
                raise "Timeout reached on accept request."
              end
              # close the listening socket
              bsock.close
              # verify the connection is from the dest_ip origionally specified by the client
              rpeer = @rsock.getpeername_as_array
              raise "Got connection from an invalid peer." if( rpeer[HOST] != request.dest_ip )
              # send back the client connect success to the client
              # sf: according to the spec we send this response back to the client, however
              #     I have seen some clients who bawk if they get this second response.
              response           = Response.new ( @lsock )
              response.version   = REPLY_VERSION
              response.command   = REPLY_FIELD_SUCCEEDED
              response.atyp      = request.atyp
              response.hostname  = request.hostname
              response.dest_ip   = rpeer[HOST]
              response.dest_port = rpeer[PORT]
              response.send()
            else
              raise "Unknown request command received #{request.command} received."
            end
          rescue Rex::ConnectionRefused, Rex::HostUnreachable, Rex::InvalidDestination, Rex::ConnectionTimeout => e
            # send back failure to the client
            response           = Response.new ( @lsock )
            response.version   = REPLY_VERSION
            response.atyp      = request.atyp
            response.dest_port = request.dest_port
            response.dest_ip   = request.dest_ip
            if e.class == Rex::ConnectionRefused
              response.command   = REPLY_FIELD_CONNECTION_REFUSED
              response.send()
              raise "Connection refused by destination (#{request.dest_ip}:#{request.dest_port})"
            elsif e.class == Rex::ConnectionTimeout
              response.command   = REPLY_FIELD_HOST_UNREACHABLE
              response.send()
              raise "Connection attempt timed out (#{request.dest_ip}:#{request.dest_port})"
            elsif e.class == Rex::HostUnreachable
              response.command   = REPLY_FIELD_HOST_UNREACHABLE
              response.send()
              raise "Host Unreachable (#{request.dest_ip}:#{request.dest_port})"
            elsif e.class == Rex::NetworkUnreachable
              response.command   = REPLY_FIELD_NETWORK_UNREACHABLE
              response.send()
              raise "Network unreachable (#{request.dest_ip}:#{request.dest_port})"
            end
          rescue RuntimeError
            raise
            # TODO: This happens when we get a connection refused for an IPv6 connection.  :-(
            #       It's unknown if that's the only error case.
          rescue => e
            raise
            response           = Response.new ( @lsock )
            response.version   = REPLY_VERSION
            response.atyp      = request.atyp
            response.dest_port = request.dest_port
            response.dest_ip   = request.dest_ip
            response.hostname  = request.hostname
            response.command   = REPLY_FIELD_SOCKS_SERVER_FAILURE
            response.send()
            # raise an exception to close this client connection
            raise e
          end
          # setup the two way relay for full duplex io
          @lsock.extend( Relay )
          @rsock.extend( Relay )
          # start the socket relays...
          @lsock.relay( self, @rsock )
          @rsock.relay( self, @lsock )
        rescue
          #raise                            # UNCOMMENT FOR DEBUGGING
          wlog( "SOCKS5: #{$!}" )
          wlog( "SOCKS5: #{$!.message}" )
          self.stop
        end
      end
    end

    # Stop handling the client connection.
    def stop
      @mutex.synchronize do
        if( not @closed )

          begin
            @lsock.close if @lsock
          rescue
          end

          begin
            @rsock.close if @rsock
          rescue
          end

          @client_thread.kill if( @client_thread and @client_thread.alive? )

          @server.remove_client( self )

          @closed = true
        end
      end
    end

  end

  # Create a new Socks5 server.
  def initialize( opts={} )
    @opts          = { 'SRVHOST' => '0.0.0.0', 'SRVPORT' => 1080,
                       'USERNAME' => nil, 'PASSWORD' => nil }
    @opts          = @opts.merge( opts['Context']['MsfExploit'].datastore )
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
  # Start the Socks5 server.
  #
  def start
      begin
        # create the servers main socket (ignore the context here because we don't want a remote bind)
        @server = Rex::Socket::TcpServer.create( 'LocalHost' => @opts['SRVHOST'], 'LocalPort' => @opts['SRVPORT'] )
        # signal we are now running
        @running = true
        # start the servers main thread to pick up new clients
        @server_thread = Rex::ThreadFactory.spawn("SOCKS5ProxyServer", false) do
          while( @running ) do
            begin
              # accept the client connection
              sock = @server.accept
              # and fire off a new client instance to handle it
              Client.new( self, sock, @opts ).start
            rescue
              wlog( "Socks5.start - server_thread - #{$!}" )
            end
          end
        end
      rescue
        wlog( "Socks5.start - #{$!}" )
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
  # Stop the Socks5 server.
  #
  def stop
    if( @running )
      # signal we are no longer running
      @running = false
      # stop any clients we have (create a new client array as client.stop will delete from @clients)
      clients = []
      clients.concat( @clients )
      clients.each do | client |
        client.stop
      end
      # close the server socket
      @server.close if @server
      # if the server thread did not terminate gracefully, kill it.
      @server_thread.kill if( @server_thread and @server_thread.alive? )
    end
    return !@running
  end

  def add_client( client )
    @clients << client
  end

  def remove_client( client )
    @clients.delete( client )
  end

  attr_reader :opts

end

end; end; end

