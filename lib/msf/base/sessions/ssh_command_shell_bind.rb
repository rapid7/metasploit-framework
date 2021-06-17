# -*- coding: binary -*-

# todo: refactor this so it's no longer under Meterpreter so it can be used elsewhere
require 'rex/post/meterpreter/channels/socket_abstraction'

module Msf::Sessions

class SshCommandShellBind < Msf::Sessions::CommandShell

  include Msf::Session::Comm

  class TcpClientChannel # taken from Meterpreter
    include Rex::IO::StreamAbstraction

    def initialize(client, channel, params)
      initialize_abstraction

      @client = client
      @channel = channel
      @params = params

      lsock.extend(Rex::Post::Meterpreter::SocketAbstraction::SocketInterface)
      lsock.channel = self

      rsock.extend(Rex::Post::Meterpreter::SocketAbstraction::SocketInterface)
      rsock.channel = self
    end

    def read(length = nil)
      # todo: figure out how this should handle incomplete reads, timeouts etc to be just like meterpreter
      raise ::NotImplementedError
    end

    def write(buffer)
      channel.send_data(buffer)
      buffer.length
    end

    attr_reader :channel
    attr_reader :client
    attr_reader :params
  end

  def create(param)
    # Notify handlers before we create the socket
    notify_before_socket_create(self, param)

    if param.proto == 'tcp' && !param.server
      ssh_channel = @ssh_socket.open_channel('direct-tcpip', :string, param.peerhost, :long, param.peerport, :string, param.localhost, :long, param.localport) do |achannel|
        $stderr.puts 'direct channel established'
      end
    end

    # raise ::Rex::ConnectionError.new ?
    raise RuntimeError.new('failed to open the channel') if ssh_channel.nil?

    # Notify now that we've created the socket
    #notify_socket_created(self, sock, param)

    msf_channel = TcpClientChannel.new(self, ssh_channel, param)
    @channels << msf_channel

    ssh_channel.on_close do |ch|
      $stderr.puts "closing rsock via on_close"
      msf_channel.rsock.close
    end

    ssh_channel.on_eof do |ch|
      $stderr.puts "closing rsock via on_eof"
      msf_channel.rsock.close
    end

    ssh_channel.on_data do |ch, data|
      $stderr.puts "writing #{data.length} bytes to rsock"
      msf_channel.rsock.syswrite(data)  # #syswrite selected from SocketAbstraction#dio_write_handler
    end

    # Return the socket to the caller
    msf_channel.lsock
  end

  def initialize(ssh_socket, conn, opts = {})
    # this is required to add the #getpeername_as_array method that's used by SocketInterface#getsockname
    conn.extend(Rex::Socket)

    @ssh_socket = ssh_socket
    @channels = []
    super(conn, opts)
  end

  alias sock rstream
  attr_reader :ssh_socket

  def self.from_ssh_socket(ssh_socket, opts = {})
    command_stream = Net::SSH::CommandStream.new(ssh_socket)
    self.new(ssh_socket, command_stream.lsock, opts)
  end
end

end
