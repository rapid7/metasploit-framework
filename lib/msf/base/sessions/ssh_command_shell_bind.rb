# -*- coding: binary -*-


module Msf::Sessions

class SshCommandShellBind < Msf::Sessions::CommandShell

  include Msf::Session::Comm

  module DirectChannelWrite

    def write(buf, opts = nil)
      syswrite(buf)
    end

    def syswrite(buf)
      channel.channel.send_data(buf)
      buf.length
    end

    attr_accessor :channel
  end

  module SocketInterface # taken from Meterpreter
    include Rex::Socket

    def getsockname
      return super if not channel
      # Find the first host in our chain (our address)
      hops = 0
      csock = channel.client.sock
      while(csock.respond_to?('channel'))
        csock = csock.channel.client.sock
        hops += 1
      end
      _address_family,caddr,_cport = csock.getsockname
      address_family,raddr,_rport = csock.getpeername_as_array
      _maddr,mport = [ channel.params.localhost, channel.params.localport ]
      [ address_family, "#{caddr}#{(hops > 0) ? "-_#{hops}_" : ""}-#{raddr}", mport ]
    end

    def getpeername
      return super if not channel
      maddr,mport = [ channel.params.peerhost, channel.params.peerport ]
      ::Socket.sockaddr_in(mport, maddr)
    end

    %i{localhost localport peerhost peerport}.map do |meth|
      define_method(meth) {
        return super if not channel
        channel.params.send(meth)
      }
    end

    def close
      super
      channel.cleanup_abstraction
      channel.close
    end

    attr_accessor :channel

    def type?
      'tcp'
    end
  end

  class TcpClientChannel # taken from Meterpreter
    include Rex::IO::StreamAbstraction

    def initialize(channel, param)
      initialize_abstraction

      @channel = channel
      @params = param

      lsock.extend(SocketInterface)
      lsock.extend(DirectChannelWrite)
      lsock.channel = self

      rsock.extend(SocketInterface)
      rsock.channel = self
    end

    def close
      cleanup_abstraction
    end

    attr_reader :channel
    attr_reader :params
  end

  def create(param)
    sock = nil

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

    msf_channel = TcpClientChannel.new(ssh_channel, param)
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
      msf_channel.rsock.syswrite(data)
    end

    # Return the socket to the caller
    msf_channel.lsock
  end

  def initialize(ssh_socket, conn, opts = {})
    @ssh_socket = ssh_socket
    @channels = []
    super(conn, opts)
  end

  attr_reader :ssh_socket

  def self.from_ssh_socket(ssh_socket, opts = {})
    command_stream = Net::SSH::CommandStream.new(ssh_socket)
    self.new(ssh_socket, command_stream.lsock, opts)
  end
end

end
