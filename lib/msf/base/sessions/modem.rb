# -*- coding: binary -*-

require 'rex/post/channel'
require 'rex/post/meterpreter/channels/socket_abstraction'
require 'rex/io/datagram_abstraction'
require 'rex/socket/udp'

module Msf
module Sessions

###
#
# Abstract base class for modem-backed pivot sessions.
#
# A modem session implements Msf::Session::Comm so that the framework can
# open arbitrary TCP connections through the modem natively (route add,
# autoroute, etc.) without a SOCKS proxy in the middle.
#
# Subclasses implement the protected create_tcp_client_channel,
# create_tcp_server_channel, and create_udp_channel hooks. The base raises
# NotImplementedError for each so missing implementations surface clearly
# during development.
#
# The generic TcpClientChannel inner class works with any connection object
# that satisfies the duck-type interface:
#
#   recv      -> blocks until String data or nil EOF
#   send(buf) -> sends buf to the remote host
#   close     -> tears down the connection
#
###
class Modem
  include Msf::Session
  include Msf::Session::Comm
  include Rex::Post::Channel::Container
  # Provides user_input= / user_output= attr_accessors required by
  # Msf::Session#set_from_exploit. Interactive sessions get these via
  # Session::Interactive -> Rex::Ui::Interactive -> Rex::Ui::Subscriber.
  # Non-interactive sessions (like this one) must include it directly.
  include Rex::Ui::Subscriber

  # Shared socket name interface for modem channels.
  #
  # Rex::Post::Channel::SocketAbstraction::SocketInterface#getsockname
  # traverses a Meterpreter-style channel chain via channel.client.sock,
  # which doesn't apply here. Override it to return a synthetic local
  # address from the channel params so callers (e.g. the SOCKS5 response
  # builder) get a valid value rather than a NoMethodError. Both the TCP
  # and UDP channel SocketInterfaces mix this in.
  module ChannelSocketInterface
    include Rex::Post::Channel::SocketAbstraction::SocketInterface

    def close(*args)
      current_channel = channel if respond_to?(:channel)
      super
    ensure
      current_channel.close if current_channel && !current_channel.closed?
    end

    def getsockname
      return super unless channel

      [ ::Socket::AF_INET,
        channel.params.localhost || '0.0.0.0',
        channel.params.localport || 0 ]
    end
  end

  class ChannelBase
    def initialize(session, cid, conn, params)
      @session = session
      @cid = cid
      @conn = conn
      @params = params
      @mutex = Mutex.new
      @remote_closed = false
    end

    def closed?
      @cid.nil?
    end

    def remote_closed?
      @mutex.synchronize { @remote_closed }
    end

    def remote_closed
      return unless mark_remote_closed

      notify_remote_closed
      close_connection
    end

    def close
      cid = nil
      should_close_connection = false
      @mutex.synchronize do
        return if closed?

        cid = @cid
        should_close_connection = !@remote_closed
        @cid = nil
        @remote_closed = true
      end

      close_connection if should_close_connection
      stop_reader_thread
      @session.remove_channel(cid)
      cleanup_abstraction
    end

    attr_reader :cid, :params

    private

    def mark_remote_closed
      @mutex.synchronize do
        return false if closed? || @remote_closed

        @remote_closed = true
      end
      true
    end

    def notify_remote_closed
    end

    def spawn_reader_thread(name, &block)
      framework = @session.framework
      thread_manager = framework.threads if framework.respond_to?(:threads)
      unless thread_manager.respond_to?(:spawn)
        raise 'Modem channels require a framework thread manager'
      end

      thread_manager.spawn(name, false, &block)
    end

    def start_reader_thread(name)
      @reader_thread = spawn_reader_thread(name) do
        while (data = @conn.recv)
          break unless yield(data)
        end
        remote_closed if data.nil?
      end
    end

    def send_to_connection(buf, length = nil)
      raise IOError, 'Channel has been closed.' if closed? || remote_closed?

      buf = buf[0, length] if length && buf.length >= length
      @conn.send(buf)
      buf.length
    end

    def stop_reader_thread
      return unless @reader_thread
      return if @reader_thread == ::Thread.current

      @reader_thread.kill
      @reader_thread.join
    end

    def close_connection
      @conn.close
    rescue ::StandardError
      nil
    end
  end

  # -----------------------------------------------------------------------
  # Generic TCP client channel
  #
  # Uses Rex::Post::Channel::StreamAbstraction to create an lsock/rsock pair.
  # A dedicated reader thread drains recv from the underlying modem
  # connection and writes into rsock, making data visible to lsock readers.
  # The framework writes outbound data via write(), which forwards to the
  # connection's send() method.
  # -----------------------------------------------------------------------
  class TcpClientChannel < ChannelBase
    include Rex::Post::Channel::StreamAbstraction

    module SocketInterface
      include ChannelSocketInterface

      def type?
        'tcp'
      end
    end

    def monitor_rsock(name = 'ModemTcpClientRemote')
      monitor_sock(rsock, sink: self, name: name, on_exit: method(:close))
    end

    #
    # Create a new TcpClientChannel.
    #
    # @param session [Modem]           parent session
    # @param cid     [Integer]         channel ID, unique within the session
    # @param conn    [#recv]           modem connection object
    # @param params  [Rex::Socket::Parameters]
    #
    def initialize(session, cid, conn, params)
      initialize_abstraction
      super

      start_reader_thread('ModemTcpClientChannelReader') do |data|
        rsock.syswrite(data)
        true
      rescue ::StandardError
        false
      end

      lsock.extend(SocketInterface)
      lsock.channel = self
      rsock.extend(SocketInterface)
      rsock.channel = self

      lsock.synchronize_access { lsock.initsock(params) }
      rsock.synchronize_access { rsock.initsock(params) }

      session.add_channel(self)
    end

    #
    # Send data toward the remote host through the modem connection.
    #
    def write(buf, length = nil)
      send_to_connection(buf, length)
    end

    private

    def notify_remote_closed
      begin
        rsock.shutdown(::Socket::SHUT_WR)
      rescue ::StandardError
        nil
      end
    end
  end

  # -----------------------------------------------------------------------
  # Generic UDP channel
  #
  # Mirrors the Meterpreter UDP channel
  # (Rex::Post::Meterpreter::Extensions::Stdapi::Net::SocketSubsystem::UdpChannel):
  # it builds a real UDP socketpair via Rex::IO::DatagramAbstraction and hands
  # the framework an lsock extended with Rex::Socket::Udp, so the returned
  # object is a drop-in UDPSocket-alike (send/sendto/recv/recvfrom/read/write).
  #
  # Outbound datagrams are routed to the modem connection's send() via the
  # DirectChannelWrite mixin; inbound datagrams drained from recv are
  # written into rsock followed by the sender's sockaddr (the same two-write
  # trick Meterpreter's Datagram#dio_write_handler uses) so recvfrom() can
  # reconstruct [data, host, port].
  # -----------------------------------------------------------------------
  class UdpChannel < ChannelBase
    include Rex::IO::DatagramAbstraction

    #
    # Routes lsock writes (Rex::Socket::Udp#write/#sendto -> syswrite) straight
    # to the channel, which forwards them to the modem connection, instead of
    # into the local socketpair. Mirrors Meterpreter's DirectChannelWrite.
    #
    module DirectChannelWrite
      def syswrite(buf)
        channel.dio_write(buf)
      end

      attr_accessor :channel
    end

    module SocketInterface
      include ChannelSocketInterface

      MAX_SOCKADDR_LENGTH = 128

      def type?
        'udp'
      end

      #
      # The reader thread writes each datagram into rsock followed by its
      # sockaddr, so a recvfrom() pulls the data datagram then the sockaddr
      # datagram back off the pair. Mirrors Datagram::SocketInterface.
      #
      def recvfrom_nonblock(length, flags = 0)
        data     = super(length, flags)[0]
        sockaddr = super(MAX_SOCKADDR_LENGTH, flags)[0]
        [data, sockaddr]
      end

      #
      # UDPSocket#send-compatible signature. The modem connection is bound to a
      # single peer (AT+QIOPEN "UDP","host",port), so the explicit host/port are
      # accepted to satisfy the interface but the datagram always goes to that
      # peer.
      #
      def send(buf, _flags = 0, _a = nil, _b = nil)
        channel.dio_write(buf)
        buf.length
      end
    end

    #
    # Create a new UdpChannel.
    #
    # @param session [Modem]           parent session
    # @param cid     [Integer]         channel ID, unique within the session
    # @param conn    [#recv]           modem connection object
    # @param params  [Rex::Socket::Parameters]
    #
    def initialize(session, cid, conn, params)
      initialize_abstraction
      super

      lsock.extend(Rex::Socket::Udp)
      lsock.initsock
      lsock.extend(SocketInterface)
      lsock.extend(DirectChannelWrite)
      lsock.channel = self

      rsock.extend(SocketInterface)
      rsock.channel = self

      @sockaddr = Rex::Socket.to_sockaddr(@params.peerhost, @params.peerport)
      start_reader_thread('ModemUdpChannelReader') do |data|
        if data.is_a?(::String) && !data.empty?
          rsock.syswrite(data)
          rsock.syswrite(@sockaddr)
        end
        true
      rescue ::StandardError
        false
      end

      session.add_channel(self)
    end

    #
    # Send a datagram toward the peer through the modem connection. Invoked by
    # the lsock's DirectChannelWrite#syswrite and SocketInterface#send.
    #
    def dio_write(buf)
      send_to_connection(buf)
    end
  end

  # -----------------------------------------------------------------------
  # Session identity - subclasses should override desc
  # -----------------------------------------------------------------------

  def self.type
    'modem'
  end

  def type
    self.class.type
  end

  def desc
    'Modem'
  end

  def platform
    'hardware'
  end

  def arch
    ARCH_CMD
  end

  def self.can_cleanup_files
    false
  end

  def alive?
    self.alive
  end

  # Modem sessions are never interactively attached to a terminal.
  def interacting
    false
  end

  def interactive?
    false
  end

  # Base implementation: modem sessions cannot natively tunnel UDP in the
  # general case.
  #
  # Note: returning false here causes the framework's DNS resolver to fall
  # back to TCP-DNS, which would route through the modem and add significant
  # latency. Subclasses that override this to true must also implement
  # create_udp_channel so DNS and UDP traffic route correctly.
  def supports_udp?
    false
  end

  # -----------------------------------------------------------------------
  # Msf::Session::Comm - dispatches to subclass hooks
  # -----------------------------------------------------------------------

  #
  # Called by Rex::Socket::SwitchBoard to open a new socket through this
  # session. Dispatches to the appropriate protected hook method.
  #
  # @param params [Rex::Socket::Parameters]
  # @return [Socket-like] the local socket end for the framework to use
  # @raise [Rex::ConnectionError] on unsupported protocol or open failure
  #
  def create(params)
    notify_before_socket_create(self, params)

    sock = case params.proto
    when 'udp'
      create_udp_channel(params)
    when 'tcp'
      if params.server
        create_tcp_server_channel(params)
      else
        create_tcp_client_channel(params)
      end
    else
      raise ::Rex::ConnectionError.new(params.peerhost, params.peerport,
        reason: "Unsupported socket protocol: #{params.proto}")
    end

    raise ::Rex::ConnectionError unless sock
    notify_socket_created(self, sock, params)
    sock
  end

  # -----------------------------------------------------------------------
  # Lifecycle
  # -----------------------------------------------------------------------

  def initialize(opts = {})
    super()              # Msf::Session#initialize: sets alive, uuid, routes
    @channel_ticker = 0
    initialize_channels  # Rex::Post::Channel::Container
    self.alive = true
  end

  def cleanup
    channels.dup.each_value(&:close)
    super
  end

  protected

  def create_tcp_client_channel(_params)
    raise NotImplementedError, "#{self.class}#create_tcp_client_channel is not implemented"
  end

  def create_tcp_server_channel(_params)
    raise NotImplementedError, "#{self.class}#create_tcp_server_channel is not implemented"
  end

  #
  # Base UDP fallback: delegate to the local system comm.
  #
  def create_udp_channel(params)
    raise NotImplementedError, "#{self.class}#create_udp_channel is not implemented"
  end
end

end  # Sessions
end  # Msf
