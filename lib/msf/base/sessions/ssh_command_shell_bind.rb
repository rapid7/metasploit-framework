# -*- coding: binary -*-

# todo: refactor this so it's no longer under Meterpreter so it can be used elsewhere
require 'rex/post/meterpreter/channel_container'
require 'rex/post/meterpreter/channels/socket_abstraction'

module Msf::Sessions

class SshCommandShellBind < Msf::Sessions::CommandShell

  include Msf::Session::Comm
  include Rex::Post::Meterpreter::ChannelContainer

  class TcpClientChannel # taken from Meterpreter
    include Rex::IO::StreamAbstraction

    def initialize(client, cid, ssh_channel, params)
      initialize_abstraction

      @client = client
      @cid = cid
      @ssh_channel = ssh_channel
      @params = params

      ssh_channel.on_close do |ch|
        $stderr.puts "in #on_close(#{ch.inspect})"
        rsock.close
      end

      ssh_channel.on_data do |ch, data|
        $stderr.puts "in #on_data(#{ch.inspect}, #{data.inspect})"
        rsock.syswrite(data)  # #syswrite selected from SocketAbstraction#dio_write_handler
      end

      ssh_channel.on_eof do |ch|
        $stderr.puts "in #on_eof(#{ch.inspect})"
        rsock.close
      end

      lsock.extend(Rex::Post::Meterpreter::SocketAbstraction::SocketInterface)
      lsock.channel = self

      rsock.extend(Rex::Post::Meterpreter::SocketAbstraction::SocketInterface)
      rsock.channel = self

      client.add_channel(self)
    end

    def closed?
      @cid.nil?
    end

    def close
      return if @cid.nil?

      cleanup_abstraction
      @ssh_channel.close
      @client.remove_channel(@cid)
      @cid = nil
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

  def initialize(ssh_connection, rstream, opts = {})
    @ssh_connection = ssh_connection
    @sock = ssh_connection.transport.socket
    initialize_channels
    @channel_ticker = 0
    super(rstream, opts)
  end

  def create(param)
    # Notify handlers before we create the socket
    notify_before_socket_create(self, param)

    mutex = Mutex.new
    condition = ConditionVariable.new
    ssh_channel = msf_channel = nil

    if param.proto == 'tcp' && !param.server
      ssh_channel = @ssh_connection.open_channel('direct-tcpip', :string, param.peerhost, :long, param.peerport, :string, param.localhost, :long, param.localport) do |new_channel|
        $stderr.puts 'direct channel established'
        msf_channel = TcpClientChannel.new(self, @channel_ticker += 1, new_channel, param)
        mutex.synchronize {
          condition.signal
        }
      end
    end

    raise ::Rex::ConnectionError.new if ssh_channel.nil?

    ssh_channel.on_open_failed do |ch, code, desc|
      $stderr.puts "in #on_open_failed(#{ch.inspect}, #{code.inspect}, #{desc.inspect})"
      mutex.synchronize {
        condition.signal
      }
    end

    mutex.synchronize {
      condition.wait(mutex, param.timeout)
    }

    raise ::Rex::ConnectionError.new if msf_channel.nil?

    sock = msf_channel.lsock

    # Notify now that we've created the socket
    notify_socket_created(self, sock, param)
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

  def self.from_ssh_socket(ssh_connection, opts = {})
    command_stream = Net::SSH::CommandStream.new(ssh_connection)
    self.new(ssh_connection, command_stream.lsock, opts)
  end
end

end
