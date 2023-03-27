class Rex::Proto::Amqp::Version091::Client

  require 'rex/stopwatch'
  require 'rex/proto/amqp/error'
  require 'rex/proto/amqp/version_0_9_1/frames'
  require 'rex/proto/amqp/version_0_9_1/client/channel'

  include Rex::Proto::Amqp

  # @return [String] The AMQP server host.
  attr_reader :host

  # @return [Integer] The AMQP server port.
  attr_reader :port

  # @return [Boolean] Whether or not SSL is used for the connection.
  attr_reader :ssl

  # @return [Rex::Socket::Comm] An optional, explicit object to use for creating the connection.
  attr_reader :comm

  # @return [Hash] A hash containing server information.
  attr_reader :server_info

  # @!attribute timeout
  #   @return [Integer] The communication timeout in seconds.
  attr_accessor :timeout

  # @param [String] host The AMQP server host.
  # @param [Integer,NilClass] port The AMQP server port or nil for automatic based on ssl.
  # @param [Boolean] ssl Whether or not SSL is used for the connection.
  # @param [String] ssl_version The SSL version to use.
  # @param [Rex::Socket::Comm] comm An optional, explicit object to use for creating the connection.
  # @param [Integer] timeout The communication timeout in seconds.
  def initialize(host, port: nil, context: {}, ssl: true, ssl_version: nil, comm: nil, timeout: 10)
    if port.nil?
      port = ssl ? 5671 : 5672
    end

    @host = host
    @port = port
    @context = context
    @ssl = ssl
    @ssl_version = ssl_version
    @comm = comm
    @server_info = {}
    @channels = {}
    @frame_queue = []
    @next_channel_id = 1
    @timeout = timeout
  end

  # Establish the connection to the remote server.
  #
  # @param [Integer] t An explicit timeout to use for the connection otherwise the default will be used.
  # @return [NilClass]
  def connect(t = -1)
    timeout = (t.nil? or t == -1) ? @timeout : t

    @conn = Rex::Socket::Tcp.create(
      'PeerHost'   => @host,
      'PeerPort'   => @port.to_i,
      'Context'    => @context,
      'SSL'        => @ssl,
      'SSLVersion' => @ssl_version,
      'Timeout'    => timeout,
      'Comm'       => @comm
    )

    nil
  end

  # Close the connection to the remote server.
  #
  # @return [NilClass]
  def close
    if @conn && !@conn.closed?
      @conn.shutdown
      @conn.close
    end

    @conn = nil
  end

  # Login to the remote server. The connection will be started automatically if it has not already been established.
  #
  # @param [String] username The username to authenticate with.
  # @param [String] password The password to authenticate with.
  # @param [String] vhost The virtual host to connect to.
  # @return [Boolean] Whether or not authentication was successful.
  def login(username, password, vhost: '/')
    connect if @conn.nil?

    send_protocol_header
    connection_start(username, password)

    resp = recv_frame
    if is_method_frame?(resp, Version091::Frames::MethodArguments::AmqpVersion091ConnectionClose)
      close
      return false
    elsif !is_method_frame?(resp, Version091::Frames::MethodArguments::AmqpVersion091ConnectionTune)
      raise Error::UnexpectedReplyError.new(resp)
    end

    @server_info[:tuning] = resp.arguments.snapshot
    connection_tune_ok = Version091::Frames::AmqpVersion091MethodFrame.new
    connection_tune_ok.arguments = Version091::Frames::MethodArguments::AmqpVersion091ConnectionTuneOk.new(
      resp.arguments.snapshot
    )
    send_frame(connection_tune_ok)

    connection_open(vhost)

    true
  end

  # Send a frame to the connected peer.
  #
  # @param [#to_binary_s] frame The frame to send.
  # @return [Integer] The number of bytes written.
  def send_frame(frame)
    @conn.put(frame.to_binary_s)
  end

  # Receive a frame from the connected peer with a timeout.
  #
  # @return [BinData::Record] The frame that was received.
  def recv_frame
    remaining = @timeout
    header_raw, elapsed_time = Rex::Stopwatch.elapsed_time do
      num_bytes = Version091::Frames::AmqpVersion091FrameHeader.new.num_bytes
      @conn.get_once(num_bytes, remaining)
    end
    remaining -= elapsed_time

    header = Version091::Frames::AmqpVersion091FrameHeader.read(header_raw)
    body = ''
    while (body.size < (header.frame_size + 1)) && remaining > 0
      chunk, elapsed_time = Rex::Stopwatch.elapsed_time do
        @conn.read((header.frame_size + 1) - body.size, remaining)
      end
      remaining -= elapsed_time
      body << chunk
    end

    unless body.size == (header.frame_size + 1)
      if remaining <= 0
        raise Rex::TimeoutError, 'Failed to read the response data due to timeout.'
      end

      Error::InvalidFrameError.new
    end

    case header.frame_type
    when 1
      frame = Version091::Frames::AmqpVersion091MethodFrame.read(header.to_binary_s + body)
    when 2
      frame = Version091::Frames::AmqpVersion091ContentHeaderFrame.read(header.to_binary_s + body)
    when 3
      frame = Version091::Frames::AmqpVersion091ContentBodyFrame.read(header.to_binary_s + body)
    end

    frame
  end

  # Open a new channel.
  #
  # @return [Channel] The newly opened channel.
  def channel_open
    ch_open = Version091::Frames::AmqpVersion091MethodFrame.new
    ch_open.header.frame_channel = cid = @next_channel_id
    ch_open.arguments = Version091::Frames::MethodArguments::AmqpVersion091ChannelOpen.new
    send_frame(ch_open)
    resp = recv_frame

    unless is_method_frame?(resp, Version091::Frames::MethodArguments::AmqpVersion091ChannelOpenOk)
      raise Error::UnexpectedReplyError.new(resp)
    end

    @next_channel_id += 1
    @channels[cid] = Channel.new(self, cid)
  end

  # Close an established channel.
  #
  # @param [Channel] channel The channel object to close.
  # @return [NilClass]
  def channel_close(channel)
    ch_close = Version091::Frames::AmqpVersion091MethodFrame.new
    ch_close.header.frame_channel = channel.id
    ch_close.arguments = Version091::Frames::MethodArguments::AmqpVersion091ChannelClose.new
    send_frame(ch_close)
    resp = recv_frame

    unless is_method_frame?(resp, Version091::Frames::MethodArguments::AmqpVersion091ChannelCloseOk)
      raise Error::UnexpectedReplyError.new(resp)
    end

    @channels.delete(channel.id)
    nil
  end

  # Close the established connection by performing the necessary handshake.
  #
  # @return [NilClass]
  def connection_close
    send_connection_close
    recv_connection_close_ok

    nil
  end

  # Open a connection by performing the necessary handshake.
  #
  # @param [String] vhost The virtual host to connect to.
  # @return [NilClass]
  def connection_open(vhost)
    send_connection_open(virtual_host: vhost)
    recv_connection_open_ok

    nil
  end

  # Start a connection by performing the necessary handshake. The caller needs to validate the response to ensure
  # authentication succeeded.
  #
  # @param [String] username The username to authenticate with.
  # @param [String] password The password to authenticate with.
  # @return [NilClass]
  def connection_start(username, password)
    recv_connection_start

    unless @server_info[:security_mechanisms].include?('PLAIN')
      # PLAIN is supported by default, others can be added via plugins
      raise Error::NegotiationError.new('There are no mutually supported authentication mechanisms.')
    end

    # prefer en_US if it's available, otherwise select one at random
    if @server_info[:locales].include?('en_US')
      locale = 'en_US'
    else
      locale = @server_info[:locales].sample
    end

    send_connection_start_ok({
      # Per the spec, these properties "should" contain: product, version, platform, copyright, and information
      client_properties: [
        { name: 'capabilities', data: { data_type: 'F'.ord, data: [
          { name: 'authentication_failure_close', data: { data_type: 't'.ord, data: true } },
          { name: 'basic.nack', data: { data_type: 't'.ord, data: true } },
          { name: 'connection.blocked', data: { data_type: 't'.ord, data: true } },
          { name: 'consumer_cancel_notify', data: { data_type: 't'.ord, data: true } },
          { name: 'publisher_confirms', data: { data_type: 't'.ord, data: true } }
        ] } }
      ],
      # https://www.rabbitmq.com/access-control.html#mechanisms
      mechanism: 'PLAIN',
      response: build_sasl_response_plain(username, password),
      locale: locale
    })
  end

  def recv_connection_close_ok
    resp = recv_frame
    unless is_method_frame?(resp, Version091::Frames::MethodArguments::AmqpVersion091ConnectionCloseOk)
      raise Error::UnexpectedReplyError.new(resp)
    end

    resp
  end

  def recv_connection_open_ok
    resp = recv_frame
    unless is_method_frame?(resp, Version091::Frames::MethodArguments::AmqpVersion091ConnectionOpenOk)
      raise Error::UnexpectedReplyError.new(resp)
    end

    resp
  end

  def recv_connection_start
    resp = recv_frame
    unless is_method_frame?(resp, Version091::Frames::MethodArguments::AmqpVersion091ConnectionStart)
      raise Error::UnexpectedReplyError.new(resp)
    end

    @server_info = {
      properties: resp.arguments.server_properties.coerce,
      security_mechanisms: resp.arguments.mechanisms.split(' '),
      locales: resp.arguments.locales.split(' ')
    }

    resp
  end

  def send_connection_close(arguments={})
    conn_close = Version091::Frames::AmqpVersion091MethodFrame.new
    conn_close.arguments = Version091::Frames::MethodArguments::AmqpVersion091ConnectionClose.new(arguments)
    send_frame(conn_close)

    nil
  end

  def send_connection_open(arguments={})
    connection_open = Version091::Frames::AmqpVersion091MethodFrame.new
    connection_open.arguments = Version091::Frames::MethodArguments::AmqpVersion091ConnectionOpen.new(arguments)
    send_frame(connection_open)

    nil
  end

  def send_connection_start_ok(arguments={})
    connection_start_ok = Version091::Frames::AmqpVersion091MethodFrame.new
    connection_start_ok.arguments = Version091::Frames::MethodArguments::AmqpVersion091ConnectionStartOk.new(arguments)
    send_frame(connection_start_ok)

    nil
  end

  def send_protocol_header
    send_frame(Version091::Frames::AmqpVersion091ProtocolHeader.new)

    nil
  end

  private

  # Build a SASL authentication response for a username and password.
  #
  # @param [String] username
  # @param [String] password
  # @return [String]
  def build_sasl_response_plain(username, password)
    # per the SASL spec, username and password must be UTF-8 encoded
    # see: https://www.rfc-editor.org/rfc/rfc4616#section-2
    "\x00".b + username.encode('UTF-8') + "\x00".b + password.encode('UTF-8')
  end

  # Check if a frame is a method frame, and (optionally) if it's of the specified type.
  #
  # @param [BinData::Record] resp The object to verify is a method frame.
  # @param [BinData::Record] klass The method argument class to check.
  # @return [Boolean]
  def is_method_frame?(resp, klass=nil)
    return false unless resp.is_a?(Version091::Frames::AmqpVersion091MethodFrame)

    if klass
      return false unless resp.class_id == klass::CLASS_ID
      return false unless resp.method_id == klass::METHOD_ID
    end

    true
  end
end
