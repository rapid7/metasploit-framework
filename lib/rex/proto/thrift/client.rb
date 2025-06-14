require 'rex/stopwatch'

class Rex::Proto::Thrift::Client
  include Rex::Proto::Thrift

  # @return [String] The Thrift server host.
  attr_reader :host

  # @return [Integer] The Thrift server port.
  attr_reader :port

  # @return [Boolean] Whether or not SSL is used for the connection.
  attr_reader :ssl

  # @return [Rex::Socket::Comm] An optional, explicit object to use for creating the connection.
  attr_reader :comm

  # @!attribute timeout
  #   @return [Integer] The communication timeout in seconds.
  attr_accessor :timeout

  def initialize(host, port, context: {}, ssl: false, ssl_version: nil, comm: nil, timeout: 10)
    @host = host
    @port = port
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

  # Send raw data to the remote peer.
  #
  # @param [String] data The data to send.
  def send_raw(data)
    @conn.put([data.length].pack('N') + data)
  end

  # Receive raw data from the remote peer.
  #
  # @param [Float] timeout The timeout to use for this receive operation. Defaults to the instance timeout.
  # @raise [Rex::TimeoutError] Raised when all of the data was not received within the timeout.
  # @return [String] The received data.
  def recv_raw(timeout: @timeout)
    remaining = timeout
    frame_size, elapsed_time = Rex::Stopwatch.elapsed_time do
      @conn.get_once(4, remaining)
    end
    remaining -= elapsed_time
    if frame_size.nil? || frame_size.length < 4
      raise Rex::TimeoutError, 'Failed to read the response data length due to timeout.'
    end

    frame_size = frame_size.unpack1('N')
    body = ''
    while (body.size < frame_size) && remaining > 0
      chunk, elapsed_time = Rex::Stopwatch.elapsed_time do
        @conn.read(frame_size - body.size, remaining)
      end
      remaining -= elapsed_time
      body << chunk
    end

    unless body.size == (frame_size)
      if remaining <= 0
        raise Rex::TimeoutError, 'Failed to read the response data due to timeout.'
      end

      raise Error::InvalidFrameError.new
    end

    body
  end

  # Call the specific method on the remote peer.
  #
  # @param [String] method_name The method name to call.
  # @param [BinData::Struct, Hash, String] *data The data to send in the method call.
  # @param [Float] timeout The timeout to use for this call operation. Defaults to the instance timeout.
  # @raise [Error::UnexpectedReplyError] Raised if the reply was not to the method call.
  # @raise [Rex::TimeoutError] Raised when all of the data was not received within the timeout.
  # @return [Array<Hash>] The results of the method call.
  def call(method_name, *data, timeout: @timeout)
    tx_header = ThriftHeader.new(method_name: method_name, message_type: ThriftMessageType::CALL)
    tx_data = data.map do |part|
      case part
      when BinData::Struct
        part.to_binary_s
      when Hash
        ThriftData.new(part).to_binary_s
      else
        part
      end
    end

    send_raw(tx_header.to_binary_s + tx_data.join)
    rx_data = recv_raw(timeout: timeout)
    rx_header = ThriftHeader.read(rx_data)
    unless rx_header.message_type == ThriftMessageType::REPLY
      raise Error::UnexpectedReplyError.new(rx_header, 'The received header was not a REPLY message.')
    end

    unless rx_header.method_name == method_name
      raise Error::UnexpectedReplyError.new(rx_header, 'The received header was not to the expected method.')
    end

    ThriftStruct.read(rx_data[rx_header.num_bytes..]).snapshot
  end
end
