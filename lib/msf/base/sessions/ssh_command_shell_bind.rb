# -*- coding: binary -*-

require 'metasploit/framework/ssh/platform'
require 'rex/post/channel'
require 'rex/post/meterpreter/channels/socket_abstraction'

module Msf::Sessions
  #
  # This class provides a session for SSH client connections, where Metasploit
  # has authenticated to a remote SSH server. It is compatible with the
  # Net::SSH library.
  #
  class SshCommandShellBind < Msf::Sessions::CommandShell

    include Msf::Session::Comm
    include Rex::Post::Channel::Container

    # see: https://datatracker.ietf.org/doc/html/rfc4254#section-5.1
    module ChannelFailureReason
      SSH_OPEN_ADMINISTRATIVELY_PROHIBITED = 1
      SSH_OPEN_CONNECT_FAILED = 2
      SSH_OPEN_UNKNOWN_CHANNEL_TYPE = 3
      SSH_OPEN_RESOURCE_SHORTAGE = 4
    end

    #
    # This is a Metasploit Framework channel object that wraps a Net::SSH native
    # channel object.
    #
    class TcpClientChannel
      include Rex::Post::Channel::StreamAbstraction

      #
      # This is a common interface that socket paris are extended with to be
      # compatible with pivoting.
      #
      module SocketInterface
        include Rex::Post::Channel::SocketAbstraction::SocketInterface

        def type?
          'tcp'
        end
      end

      #
      # Create a new TcpClientChannel instance.
      #
      # @param client [SshCommandShellBind] The command shell session that this
      #   channel instance belongs to.
      # @param cid [Integer] The channel ID.
      # @param ssh_channel [Net::SSH::Connection::Channel] The connected SSH
      #   channel.
      # @param params [Rex::Socket::Parameters] The parameters that were used to
      #   open the channel.
      def initialize(client, cid, ssh_channel, params)
        initialize_abstraction

        @client = client
        @cid = cid
        @ssh_channel = ssh_channel
        @params = params
        @mutex = Mutex.new

        ssh_channel.on_close do |_ch|
          dlog('ssh_channel#on_close closing the sock')
          close
        end

        ssh_channel.on_data do |_ch, data|
          # dlog("ssh_channel#on_data received #{data.length} bytes")
          rsock.syswrite(data)
        end

        ssh_channel.on_eof do |_ch|
          dlog('ssh_channel#on_eof shutting down the socket')
          rsock.shutdown(Socket::SHUT_WR)
        end

        lsock.extend(SocketInterface)
        lsock.channel = self

        rsock.extend(SocketInterface)
        rsock.channel = self

        lsock.extend(Rex::Socket::SslTcp) if params.ssl && !params.server

        # synchronize access so the socket isn't closed while initializing, this is particularly important for SSL
        lsock.synchronize_access { lsock.initsock(params) }
        rsock.synchronize_access { rsock.initsock(params) }

        client.add_channel(self)
      end

      def closed?
        @cid.nil?
      end

      def close
        cid = @cid
        @mutex.synchronize do
          return if closed?

          @cid = nil
        end

        @client.remove_channel(cid)
        cleanup_abstraction
        @ssh_channel.close
      end

      def close_write
        if closed?
          raise IOError, 'Channel has been closed.', caller
        end

        @ssh_channel.eof!
      end

      #
      # Write *buf* to the channel, optionally truncating it to *length* bytes.
      #
      # @param [String] buf The data to write to the channel.
      # @param [Integer] length An optional length to truncate *data* to before
      #   sending it.
      def write(buf, length = nil)
        if closed?
          raise IOError, 'Channel has been closed.', caller
        end

        if !length.nil? && buf.length >= length
          buf = buf[0..length]
        end

        @ssh_channel.send_data(buf)
        buf.length
      end

      attr_reader :cid, :client, :params
    end

    # Represents an SSH reverse port forward.
    # Will receive connection messages back from the SSH server,
    # whereupon a TcpClientChannel will be opened
    class TcpServerChannel
      include Rex::IO::StreamServer

      def initialize(params, client, host, port)
        @params = params
        @client = client
        @host = host
        @port = port
        @channels = []
        @closed = false
        @mutex = Mutex.new
        @condition = ConditionVariable.new

        if params.ssl
          extend(Rex::Socket::SslTcpServer)
          initsock(params)
        end
      end

      def accept(opts = {})
        timeout = opts['Timeout']
        if (timeout.nil? || timeout <= 0)
          timeout = nil
        end

        @mutex.synchronize {
          if @channels.length > 0
            return _accept
          end
          @condition.wait(@mutex, timeout)
          return _accept
        }
      end

      def closed?
        @closed
      end

      def close
        if !closed?
          @closed = @client.stop_server_channel(@host, @port)
        end
      end

      def create(cid, ssh_channel, peer_host, peer_port)
        @mutex.synchronize {
          peer_info = {
            'PeerHost' => peer_host,
            'PeerPort' => peer_port
          }
          params = @params.merge(peer_info)
          channel = TcpClientChannel.new(@client, cid, ssh_channel, params)
          @channels.insert(0, channel)

          # Let any waiting thread know we're ready
          @condition.signal
        }
      end

      attr_reader :client

      protected

      def _accept
        result = nil
        channel = @channels.pop
        if channel
          result = channel.lsock
        end
        result
      end

    end

    #
    # Create a sessions instance from an SshConnection. This will handle creating
    # a new command stream.
    #
    # @param ssh_connection [Net::SSH::Connection] The SSH connection to create a
    #   session instance for.
    # @param opts [Hash] Optional parameters to pass to the session object.
    def initialize(ssh_connection, opts = {})
      @ssh_connection = ssh_connection
      @sock = ssh_connection.transport.socket
      @server_channels = {}

      initialize_channels
      @channel_ticker = 0

      # Be alerted to reverse port forward connections (once we start listening on a port)
      ssh_connection.on_open_channel('forwarded-tcpip', &method(:on_got_remote_connection))
      super(nil, opts)
    end

    def bootstrap(datastore = {}, handler = nil)
      # this won't work after the rstream is initialized, so do it first
      @platform = Metasploit::Framework::Ssh::Platform.get_platform(ssh_connection)

      # if the platform is known, it was recovered by communicating with the device, so skip verification, also not all
      # shells accessed through SSH may respond to the echo command issued for verification as expected
      datastore['AutoVerifySession'] &= @platform.blank?

      @rstream = Net::SSH::CommandStream.new(ssh_connection).lsock
      super

      @info = "SSH #{username} @ #{@peer_info}"
    end

    def desc
      "SSH"
    end

    #
    # Create a network socket using this session. At this time, only TCP client
    # connections can be made (like SSH port forwarding) while TCP server sockets
    # can not be opened (SSH reverse port forwarding). The SSH specification does
    # not define a UDP channel, so that is not supported either.
    #
    # @param params [Rex::Socket::Parameters] The parameters that should be used
    #   to open the socket.
    #
    # @raise [Rex::ConnectionError] If the connection fails, timesout or is not
    #   supported, a ConnectionError will be raised.
    # @return [TcpClientChannel] The connected TCP client channel.
    def create(params)
      # Notify handlers before we create the socket
      notify_before_socket_create(self, params)

      if params.proto == 'tcp'
        if params.server
          sock = create_server_channel(params)
        else
          sock = create_client_channel(params)
        end
      elsif params.proto == 'udp'
        raise ::Rex::ConnectionError.new(params.peerhost, params.peerport, reason: 'UDP sockets are not supported by SSH sessions.')
      end

      raise ::Rex::ConnectionError unless sock

      # Notify now that we've created the socket
      notify_socket_created(self, sock, params)

      sock
    end

    def create_server_channel(params)
      msf_channel = nil
      mutex = Mutex.new
      condition = ConditionVariable.new
      timed_out = false
      @ssh_connection.send_global_request('tcpip-forward', :string, params.localhost, :long, params.localport) do |success, response|
        mutex.synchronize {
          remote_port = params.localport
          remote_port = response.read_long if remote_port == 0
          if success
            if timed_out
              # We're not using the port; clean it up
              elog("Remote forwarding on #{params.localhost}:#{params.localport} succeeded after timeout. Stopping channel to clean up dangling port")
              stop_server_channel(params.localhost, remote_port)
            else
              dlog("Remote forwarding from #{params.localhost} established on port #{remote_port}")
              key = [params.localhost, remote_port]
              msf_channel = TcpServerChannel.new(params, self, params.localhost, remote_port)
              @server_channels[key] = msf_channel
            end
          else
              elog("Remote forwarding failed on #{params.localhost}:#{params.localport}")
          end
          condition.signal
        }
      end

      mutex.synchronize {
        condition.wait(mutex, params.timeout)
        unless msf_channel
          timed_out = true
        end
      }

      # Return the server channel itself
      msf_channel
    end

    def stop_server_channel(host, port)
      completed_event = Rex::Sync::Event.new
      dlog("Cancelling tcpip-forward to #{host}:#{port}")
      @ssh_connection.send_global_request('cancel-tcpip-forward', :string, host, :long, port) do |success, _response|
        if success
          key = [host, port]
          @server_channels.delete(key)
          ilog("Reverse SSH listener on #{host}:#{port} stopped")
        else
          elog("Could not stop reverse listener on #{host}:#{port}")
        end
        completed_event.set
      end
      timeout = 5 # seconds
      begin
        completed_event.wait(timeout)
        true
      rescue ::Timeout::Error
        false
      end
    end

    def create_client_channel(params)
      msf_channel = nil
      mutex = Mutex.new
      condition = ConditionVariable.new
      opened = false
      ssh_channel = @ssh_connection.open_channel('direct-tcpip', :string, params.peerhost, :long, params.peerport, :string, params.localhost, :long, params.localport) do |_|
        dlog("new direct-tcpip channel opened to #{Rex::Socket.is_ipv6?(params.peerhost) ? '[' + params.peerhost + ']' : params.peerhost}:#{params.peerport}")
        opened = true
        mutex.synchronize do
          condition.signal
        end
      end
      failure_reason_code = nil
      ssh_channel.on_open_failed do |_ch, code, desc|
        failure_reason_code = code
        wlog("failed to open SSH channel (code: #{code.inspect}, description: #{desc.inspect})")
        mutex.synchronize do
          condition.signal
        end
      end

      mutex.synchronize do
        timeout = params.timeout.to_i <= 0 ? nil : params.timeout
        condition.wait(mutex, timeout)
      end

      unless opened
        ssh_channel.close

        raise ::Rex::ConnectionTimeout.new(params.peerhost, params.peerport) if failure_reason_code.nil?

        case failure_reason_code
        when ChannelFailureReason::SSH_OPEN_ADMINISTRATIVELY_PROHIBITED
          reason = 'The SSH channel request was administratively prohibited.'
        when ChannelFailureReason::SSH_OPEN_UNKNOWN_CHANNEL_TYPE
          reason = 'The SSH channel type is not supported.'
        when ChannelFailureReason::SSH_OPEN_RESOURCE_SHORTAGE
          reason = 'The SSH channel request was denied because of a resource shortage.'
        end

        raise ::Rex::ConnectionError.new(params.peerhost, params.peerport, reason: reason)
      end
      msf_channel = TcpClientChannel.new(self, @channel_ticker += 1, ssh_channel, params)
      sock = msf_channel.lsock

      # Notify now that we've created the socket
      notify_socket_created(self, sock, params)

      sock
    end

    # The SSH server has told us that there's a port forwarding request.
    # Find the relevant server channel and inform it.
    def on_got_remote_connection(_session, channel, packet)
      connected_address = packet.read_string
      connected_port = packet.read_long
      originator_address = packet.read_string
      originator_port = packet.read_long
      ilog("Received connection: #{connected_address}:#{connected_port} <--> #{originator_address}:#{originator_port}")
      # Find the correct TcpServerChannel
      #
      key = [connected_address, connected_port]
      server_channel = @server_channels[key]
      server_channel.create(@channel_ticker += 1, channel, originator_address, originator_port)
    end

    def cleanup
      channels.each_value(&:close)
      @server_channels.each_value(&:close)

      super
    end

    attr_reader :sock, :ssh_connection
  end
end
