# -*- coding: binary -*-

# TODO: refactor this so it's no longer under Meterpreter so it can be used elsewhere
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
      include Rex::IO::StreamAbstraction

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

        lsock.extend(Rex::Socket::SslTcp) if params.ssl

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
      # Read *length* bytes from the channel. If the operation times out, the data
      # that was read will be returned or nil if no data was read.
      #
      def read(length = nil)
        if closed?
          raise IOError, 'Channel has been closed.', caller
        end

        buf = ''
        length = 65536 if length.nil?

        begin
          buf << lsock.recv(length - buf.length) while buf.length < length
        rescue StandardError
          buf = nil if buf.empty?
        end

        buf
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

      initialize_channels
      @channel_ticker = 0

      rstream = Net::SSH::CommandStream.new(ssh_connection).lsock
      super(rstream, opts)
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

      mutex = Mutex.new
      condition = ConditionVariable.new
      ssh_channel = msf_channel = nil
      opened = false

      if params.proto == 'tcp'
        if params.server
          raise ::Rex::BindFailed.new(params.localhost, params.localport, reason: 'TCP server sockets are not supported by SSH sessions.')
        end

        ssh_channel = @ssh_connection.open_channel('direct-tcpip', :string, params.peerhost, :long, params.peerport, :string, params.localhost, :long, params.localport) do |_|
          dlog("new direct-tcpip channel opened to #{Rex::Socket.is_ipv6?(params.peerhost) ? '[' + params.peerhost + ']' : params.peerhost}:#{params.peerport}")
          opened = true
          mutex.synchronize do
            condition.signal
          end
        end
      elsif params.proto == 'udp'
        raise ::Rex::ConnectionError.new(params.peerhost, params.peerport, reason: 'UDP sockets are not supported by SSH sessions.')
      end

      raise ::Rex::ConnectionError if ssh_channel.nil?

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

    def cleanup
      channels.each_value(&:close)

      super
    end

    attr_reader :sock, :ssh_connection

  end
end
