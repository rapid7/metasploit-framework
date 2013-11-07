# -*- coding: binary -*-
#
# sf - Sept 2010
#
require 'thread'
require 'rex/logging'
require 'rex/socket'

module Rex
module Proto
module Proxy

#
# A Socks4a proxy server.
#
class Socks4a

  #
  # A client connected to the Socks4a server.
  #
  class Client

    REQUEST_VERSION                 = 4
    REPLY_VERSION                   = 0

    COMMAND_CONNECT                 = 1
    COMMAND_BIND                    = 2

    REQUEST_GRANTED                 = 90
    REQUEST_REJECT_FAILED           = 91
    REQUEST_REJECT_CONNECT          = 92
    REQUEST_REJECT_USERID           = 93

    HOST                            = 1
    PORT                            = 2

    #
    # A Socks4a packet.
    #
    class Packet

      def initialize
        @version   = REQUEST_VERSION
        @command   = 0
        @dest_port = 0
        @dest_ip   = '0.0.0.0'
        @userid    = ''
      end

      #
      # A helper function to recv in a Socks4a packet byte by byte.
      #
      # sf: we could just call raw = sock.get_once but some clients
      #     seem to need reading this byte by byte instead.
      #
      def Packet.recv( sock, timeout=30 )
        raw = ''
        # read in the 8 byte header
        while( raw.length < 8 )
          raw << sock.read( 1 )
        end
        # if its a request there will be more data
        if( raw[0..0].unpack( 'C' ).first == REQUEST_VERSION )
          # read in the userid
          while( raw[8..raw.length].index( "\x00" ) == nil )
            raw << sock.read( 1 )
          end
          # if a hostname is going to be present, read it in
          ip = raw[4..7].unpack( 'N' ).first
          if( ( ip & 0xFFFFFF00 ) == 0x00000000 and ( ip & 0x000000FF ) != 0x00 )
            hostname = ''
            while( hostname.index( "\x00" ) == nil )
              hostname += sock.read( 1 )
            end
            raw << hostname
          end
        end
        # create a packet from this raw data...
        packet = Packet.new
        packet.from_r( raw ) ? packet : nil
      end

      #
      # Pack a packet into raw bytes for transmitting on the wire.
      #
      def to_r
        raw = [ @version, @command, @dest_port, Rex::Socket.addr_atoi( @dest_ip ) ].pack( 'CCnN' )
        return raw if( @userid.empty? )
        return raw + [ @userid ].pack( 'Z*' )
      end

      #
      # Unpack a raw packet into its components.
      #
      def from_r( raw )
        return false if( raw.length < 8 )
        @version   = raw[0..0].unpack( 'C' ).first
        return false if( @version != REQUEST_VERSION and @version != REPLY_VERSION )
        @command   = raw[1..1].unpack( 'C' ).first
        @dest_port = raw[2..3].unpack( 'n' ).first
        @dest_ip   = Rex::Socket.addr_itoa( raw[4..7].unpack( 'N' ).first )
        if( raw.length > 8 )
          @userid = raw[8..raw.length].unpack( 'Z*' ).first
          # if this is a socks4a request we can resolve the provided hostname
          if( self.is_hostname? )
            hostname = raw[(8+@userid.length+1)..raw.length].unpack( 'Z*' ).first
            @dest_ip = self.resolve( hostname )
            # fail if we couldnt resolve the hostname
            return false if( not @dest_ip )
          end
        else
          @userid  = ''
        end
        return true
      end

      def is_connect?
        @command == COMMAND_CONNECT ? true : false
      end

      def is_bind?
        @command == COMMAND_BIND ? true : false
      end

      attr_accessor :version, :command, :dest_port, :dest_ip, :userid

      protected

      #
      # Resolve the given hostname into a dotted IP address.
      #
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

      #
      # As per the Socks4a spec, check to see if the provided dest_ip is 0.0.0.XX
      # which indicates after the @userid field contains a hostname to resolve.
      #
      def is_hostname?
        ip = Rex::Socket.addr_atoi( @dest_ip )
        if( ip & 0xFFFFFF00 == 0x00000000 )
          return true if( ip & 0x000000FF != 0x00 )
        end
        return false
      end

    end

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
    # Create a new client connected to the server.
    #
    def initialize( server, sock )
      @server        = server
      @lsock         = sock
      @rsock         = nil
      @client_thread = nil
      @mutex         = ::Mutex.new
    end

    #
    # Start handling the client connection.
    #
    def start
      # create a thread to handle this client request so as to not block the socks4a server
      @client_thread = Rex::ThreadFactory.spawn("SOCKS4AProxyClient", false) do
        begin
          @server.add_client( self )
          # get the initial client request packet
          request = Packet.recv( @lsock )
          raise "Invalid Socks4 request packet received." if not request
          # handle the request
          begin
            # handle socks4a conenct requests
            if( request.is_connect? )
              # perform the connection request
              params = {
                'PeerHost' => request.dest_ip,
                'PeerPort' => request.dest_port,
              }
              params['Context'] = @server.opts['Context'] if @server.opts.has_key?('Context')

              @rsock = Rex::Socket::Tcp.create( params )
              # and send back success to the client
              response         = Packet.new
              response.version = REPLY_VERSION
              response.command = REQUEST_GRANTED
              @lsock.put( response.to_r )
            # handle socks4a bind requests
            elsif( request.is_bind? )
              # create a server socket for this request
              params = {
                'LocalHost' => '0.0.0.0',
                'LocalPort' => 0,
              }
              params['Context'] = @server.opts['Context'] if @server.opts.has_key?('Context')
              bsock = Rex::Socket::TcpServer.create( params )
              # send back the bind success to the client
              response           = Packet.new
              response.version   = REPLY_VERSION
              response.command   = REQUEST_GRANTED
              response.dest_ip   = '0.0.0.0'
              response.dest_port = bsock.getlocalname()[PORT]
              @lsock.put( response.to_r )
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
              rpeer = @rsock.getpeername
              raise "Got connection from an invalid peer." if( rpeer[HOST] != request.dest_ip )
              # send back the client connect success to the client
              #
              # sf: according to the spec we send this response back to the client, however
              #     I have seen some clients who bawk if they get this second response.
              #
              response           = Packet.new
              response.version   = REPLY_VERSION
              response.command   = REQUEST_GRANTED
              response.dest_ip   = rpeer[HOST]
              response.dest_port = rpeer[PORT]
              @lsock.put( response.to_r )
            else
              raise "Unknown request command received #{request.command} received."
            end
          rescue
            # send back failure to the client
            response         = Packet.new
            response.version = REPLY_VERSION
            response.command = REQUEST_REJECT_FAILED
            @lsock.put( response.to_r )
            # raise an exception to close this client connection
            raise "Failed to handle the clients request."
          end
          # setup the two way relay for full duplex io
          @lsock.extend( Relay )
          @rsock.extend( Relay )
          # start the socket relays...
          @lsock.relay( self, @rsock )
          @rsock.relay( self, @lsock )
        rescue
          wlog( "Client.start - #{$!}" )
          self.stop
        end
      end
    end

    #
    # Stop handling the client connection.
    #
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

  #
  # Create a new Socks4a server.
  #
  def initialize( opts={} )
    @opts          = { 'ServerHost' => '0.0.0.0', 'ServerPort' => 1080 }
    @opts          = @opts.merge( opts )
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
        @server = Rex::Socket::TcpServer.create( 'LocalHost' => @opts['ServerHost'], 'LocalPort' => @opts['ServerPort'] )
        # signal we are now running
        @running = true
        # start the servers main thread to pick up new clients
        @server_thread = Rex::ThreadFactory.spawn("SOCKS4AProxyServer", false) do
          while( @running ) do
            begin
              # accept the client connection
              sock = @server.accept
              # and fire off a new client instance to handle it
              Client.new( self, sock ).start
            rescue
              wlog( "Socks4a.start - server_thread - #{$!}" )
            end
          end
        end
      rescue
        wlog( "Socks4a.start - #{$!}" )
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

