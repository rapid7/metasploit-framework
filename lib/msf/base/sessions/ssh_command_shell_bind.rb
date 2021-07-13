# -*- coding: binary -*-

# todo: refactor this so it's no longer under Meterpreter so it can be used elsewhere
require 'rex/post/channel'
require 'rex/post/meterpreter/channels/socket_abstraction'

module Msf::Sessions

class SshCommandShellBind < Msf::Sessions::CommandShell

  include Msf::Session::Comm
  include Rex::Post::Channel::Container

  class TcpClientChannel
    include Rex::IO::StreamAbstraction

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

      ssh_channel.on_close do |ch|
        dlog("ssh_channel#on_close closing sock")
        close
      end

      ssh_channel.on_data do |ch, data|
        #dlog("ssh_channel#on_data received #{data.length} bytes")
        rsock.syswrite(data)
      end

      ssh_channel.on_eof do |ch|
        dlog("ssh_channel#on_eof closing sock")
        rsock.shutdown(Socket::SHUT_WR)
      end

      lsock.extend(Rex::Post::Channel::SocketAbstraction::SocketInterface)
      lsock.channel = self

      rsock.extend(Rex::Post::Channel::SocketAbstraction::SocketInterface)
      rsock.channel = self

      client.add_channel(self)
    end

    def closed?
      @cid.nil?
    end

    def close
      @mutex.synchronize {
        return if closed?
        cid = @cid
        @cid = nil
      }

      @client.remove_channel(cid)
      cleanup_abstraction
      @ssh_channel.close
    end

    #
    # Read *length* bytes from the channel. If the operation times out, the data
    # that was read will be returned or nil if no data was read.
    #
    def read(length = nil)
      if @cid.nil?
        raise IOError, 'Channel has been closed.', caller
      end

      buf = ''
      length = 65536 if length.nil?

      begin
        while buf.length < length
          buf << lsock.recv(length - buf.length)
        end
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
      if @cid.nil?
        raise IOError, 'Channel has been closed.', caller
      end

      if !length.nil? && buf.length >= length
        buf = buf[0..length]
      end

      @ssh_channel.send_data(buf)
      buf.length
    end

    attr_reader :cid
    attr_reader :client
    attr_reader :params
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

    if params.proto == 'tcp'
      if params.server
        raise ::Rex::BindFailed.new(params.localhost, params.localport, reason: 'TCP server sockets are not supported by SSH sessions.')
      end

      ssh_channel = @ssh_connection.open_channel('direct-tcpip', :string, params.peerhost, :long, params.peerport, :string, params.localhost, :long, params.localport) do |new_channel|
        msf_channel = TcpClientChannel.new(self, @channel_ticker += 1, new_channel, params)
        mutex.synchronize {
          condition.signal
        }
      end
    elsif params.proto == 'udp'
      raise ::Rex::ConnectionError.new(params.peerhost, params.peerport, reason: 'UDP sockets are not supported by SSH sessions.')
    end

    raise ::Rex::ConnectionError.new if ssh_channel.nil?

    ssh_channel.on_open_failed do |ch, code, desc|
      wlog("failed to open SSH channel (code=#{code.inspect}, description=#{desc.inspect})")
      mutex.synchronize {
        condition.signal
      }
    end

    mutex.synchronize {
      condition.wait(mutex, params.timeout)
    }

    raise ::Rex::ConnectionError.new(params.peerhost, params.peerport) if msf_channel.nil?

    sock = msf_channel.lsock

    # Notify now that we've created the socket
    notify_socket_created(self, sock, params)

    sock
  end

  def cleanup
    channels.values.each do |channel|
      channel.close
    end

    super
  end

  attr_reader :sock
  attr_reader :ssh_connection

end

end
