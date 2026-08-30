class Rex::Proto::MsNrtp::Client

  require 'rex/stopwatch'
  require 'rex/proto/ms_nrtp/ms_nrtp_message'

  include Rex::Proto::MsNrtp

  # @return [String] The MS-NRTP server host.
  attr_reader :host

  # @return [Integer] The S-NRTP server port.
  attr_reader :port

  # @return [String] The server resource component of the URI string.
  attr_reader :resource

  # @return [Boolean] Whether or not SSL is used for the connection.
  attr_reader :ssl

  # @return [Rex::Socket::Comm] An optional, explicit object to use for creating the connection.
  attr_reader :comm

  # @!attribute timeout
  #   @return [Integer] The communication timeout in seconds.
  attr_accessor :timeout

  # @param [String] host The MS-NRTP server host.
  # @param [Integer,NilClass] port The MS-NRTP server port or nil for automatic based on ssl.
  # @param [Boolean] ssl Whether or not SSL is used for the connection.
  # @param [String] ssl_version The SSL version to use.
  # @param [Rex::Socket::Comm] comm An optional, explicit object to use for creating the connection.
  # @param [Integer] timeout The communication timeout in seconds.
  def initialize(host, port, resource, context: {}, ssl: false, ssl_version: nil, comm: nil, timeout: 10)
    @host = host
    @port = port
    @resource = resource
    @context = context
    @ssl = ssl
    @ssl_version = ssl_version
    @comm = comm
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

  def recv
    remaining = @timeout
    message, elapsed_time = Rex::Stopwatch.elapsed_time do
      ::Timeout.timeout(remaining) do
        MsNrtpMessage.read(@conn)
      end
    end
    return nil unless message.operation_type == Enums::OperationTypeEnum[:Reply] && message.content_length?

    remaining -= elapsed_time
    body = ''
    while body.length < message.content_length
      chunk, elapsed_time = Rex::Stopwatch.elapsed_time do
        @conn.read(message.content_length - body.length, remaining)
      end
      remaining -= elapsed_time
      body << chunk
    end

    body
  end

  def send(data, content_type)
    message = MsNrtpMessage.new(
      content_length: data.length,
      headers: [
        { token: MsNrtpHeader::MsNrtpHeaderUri::TOKEN, header: { uri_value: "tcp://#{Rex::Socket.to_authority(@host, @port)}/#{@resource}" } },
        { token: MsNrtpHeader::MsNrtpHeaderContentType::TOKEN, header: { content_type_value: content_type } },
        { token: MsNrtpHeader::MsNrtpHeaderEnd::TOKEN }
      ]
    )
    @conn.put(message.to_binary_s + data)
  end

  def send_recv(data, content_type)
    send(data, content_type)
    recv
  end

  def send_binary(serialized_stream)
    send(serialized_stream.to_binary_s, 'application/octet-stream'.encode('UTF-8'))
  end
end
