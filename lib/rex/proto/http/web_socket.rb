# -*- coding: binary -*-

require 'bindata'
require 'rex/post/channel'

module Rex::Proto::Http::WebSocket
  class WebSocketError < StandardError
  end

  class ConnectionError < WebSocketError
    def initialize(msg: 'The WebSocket connection failed', http_response: nil)
      @message = msg
      @http_response = http_response
    end

    attr_accessor :message, :http_response
    alias to_s message
  end

  # This defines the interface that the standard socket is extended with to provide WebSocket functionality. It should be
  # used on a socket when the server has already successfully handled a WebSocket upgrade request.
  module Interface
    #
    # A channel object that allows reading and writing either text or binary data directly to the remote peer.
    #
    class Channel
      include Rex::Post::Channel::StreamAbstraction

      module SocketInterface
        include Rex::Post::Channel::SocketAbstraction::SocketInterface

        def type?
          'tcp'
        end
      end

      # The socket parameters describing the underlying connection.
      # @!attribute [r] params
      #   @return [Rex::Socket::Parameters]
      attr_reader :params

      # @param [WebSocket::Interface] websocket the WebSocket that this channel is being opened on
      # @param [nil, Symbol] read_type the data type(s) to read from the WebSocket, one of :binary, :text or nil (for both
      #   binary and text)
      # @param [Symbol] write_type the data type to write to the WebSocket
      def initialize(websocket, read_type: nil, write_type: :binary)
        initialize_abstraction

        # a read type of nil will handle both binary and text frames that are received
        raise ArgumentError, 'read_type must be nil, :binary or :text' unless [nil, :binary, :text].include?(read_type)
        raise ArgumentError, 'write_type must be :binary or :text' unless %i[binary text].include?(write_type)

        @websocket = websocket
        @read_type = read_type
        @write_type = write_type
        @mutex = Mutex.new

        # beware of: https://github.com/rapid7/rex-socket/issues/32
        _, localhost, localport = websocket.getlocalname
        _, peerhost, peerport = Rex::Socket.from_sockaddr(websocket.getpeername)
        @params = Rex::Socket::Parameters.from_hash({
          'LocalHost' => localhost,
          'LocalPort' => localport,
          'PeerHost' => peerhost,
          'PeerPort' => peerport,
          'SSL' => websocket.respond_to?(:sslctx) && !websocket.sslctx.nil?
        })

        @thread = Rex::ThreadFactory.spawn("WebSocketChannel(#{localhost}->#{peerhost})", false) do
          websocket.wsloop do |data, data_type|
            next unless @read_type.nil? || data_type == @read_type

            data = on_data_read(data, data_type)
            next if data.nil?

            rsock.syswrite(data)
          end

          close
        end

        lsock.extend(SocketInterface)
        lsock.channel = self

        rsock.extend(SocketInterface)
        rsock.channel = self
      end

      def closed?
        @websocket.nil?
      end

      def close
        @mutex.synchronize do
          return if closed?

          @websocket.wsclose
          @websocket = nil
        end

        cleanup_abstraction
      end

      #
      # Close the channel for write operations. This sends a CONNECTION_CLOSE request, after which (per RFC 6455 section
      # 5.5.1) this side must not send any more data frames.
      #
      def close_write
        if closed?
          raise IOError, 'Channel has been closed.', caller
        end

        @websocket.put_wsframe(Frame.new(header: { opcode: Opcode::CONNECTION_CLOSE }))
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

        length = buf.length
        buf = on_data_write(buf)
        if @write_type == :binary
          @websocket.put_wsbinary(buf)
        elsif @write_type == :text
          @websocket.put_wstext(buf)
        end

        length
      end

      #
      # This provides a hook point that is called when data is read from the WebSocket peer. Subclasses can intercept and
      # process the data. The default functionality does nothing.
      #
      # @param [String] data the data that was read
      # @param [Symbol] data_type the type of data that was received, either :binary or :text
      # @return [String, nil] if a string is returned, it's passed through the channel
      def on_data_read(data, _data_type)
        data
      end

      #
      # This provides a hook point that is called when data is written to the WebSocket peer. Subclasses can intercept and
      # process the data. The default functionality does nothing.
      #
      # @param [String] data the data that is being written
      # @return [String, nil] if a string is returned, it's passed through the channel
      def on_data_write(data)
        data
      end
    end

    #
    # Send a WebSocket::Frame to the peer.
    #
    # @param [WebSocket::Frame] frame the frame to send to the peer.
    def put_wsframe(frame, opts = {})
      put(frame.to_binary_s, opts = opts)
    end

    #
    # Build a WebSocket::Frame representing the binary data and send it to the peer.
    #
    # @param [String] value the binary value to use as the frame payload.
    def put_wsbinary(value, opts = {})
      put_wsframe(Frame.from_binary(value), opts = opts)
    end

    #
    # Build a WebSocket::Frame representing the text data and send it to the peer.
    #
    # @param [String] value the binary value to use as the frame payload.
    def put_wstext(value, opts = {})
      put_wsframe(Frame.from_text(value), opts = opts)
    end

    #
    # Read a WebSocket::Frame from the peer.
    #
    # @return [Nil, WebSocket::Frame] the frame that was received from the peer.
    def get_wsframe(_opts = {})
      frame = Frame.new
      frame.header.read(self)
      payload_data = ''
      while payload_data.length < frame.payload_len
        chunk = read(frame.payload_len - payload_data.length)
        if chunk.empty? # no partial reads!
          elog('WebSocket::Interface#get_wsframe: received an empty websocket payload data chunk')
          return nil
        end

        payload_data << chunk
      end
      frame.payload_data.assign(payload_data)
      frame
    rescue ::IOError
      wlog('WebSocket::Interface#get_wsframe: encountered an IOError while reading a websocket frame')
      nil
    end

    #
    # Build a channel to allow reading and writing from the WebSocket. This provides high level functionality so the
    # caller needn't worry about individual frames.
    #
    # @return [WebSocket::Interface::Channel]
    def to_wschannel(**kwargs)
      Channel.new(self, **kwargs)
    end

    #
    # Close the WebSocket. If the underlying TCP socket is still active a WebSocket CONNECTION_CLOSE request will be sent
    # and then it will wait for a CONNECTION_CLOSE response. Once completed the underlying TCP socket will be closed.
    #
    def wsclose(opts = {})
      return if closed? # there's nothing to do if the underlying TCP socket has already been closed

      # this implementation doesn't handle the optional close reasons at all
      frame = Frame.new(header: { opcode: Opcode::CONNECTION_CLOSE })
      # close frames must be masked
      # see: https://datatracker.ietf.org/doc/html/rfc6455#section-5.5.1
      frame.mask!
      put_wsframe(frame, opts = opts)
      while (frame = get_wsframe(opts))
        break if frame.nil?
        break if frame.header.opcode == Opcode::CONNECTION_CLOSE
        # all other frames are dropped after our connection close request is sent
      end

      close # close the underlying TCP socket
    end

    #
    # Run a loop to handle data from the remote end of the websocket. The loop will automatically handle fragmentation
    # unmasking payload data and ping requests. When the remote connection is closed, the loop will exit. If specified the
    # block will be passed data chunks and their data types.
    #
    def wsloop(opts = {}, &block)
      buffer = ''
      buffer_type = nil

      # since web sockets have their own tear down exchange, use a synchronization lock to ensure we aren't closed until
      # either the remote socket is closed or the teardown takes place
      @wsstream_lock = Rex::ReadWriteLock.new
      @wsstream_lock.synchronize_read do
        while (frame = get_wsframe(opts))
          frame.unmask! if frame.header.masked == 1

          case frame.header.opcode
          when Opcode::CONNECTION_CLOSE
            put_wsframe(Frame.new(header: { opcode: Opcode::CONNECTION_CLOSE }).tap { |f| f.mask! }, opts = opts)
            break
          when Opcode::CONTINUATION
            # a continuation frame can only be sent for a data frames
            # see: https://datatracker.ietf.org/doc/html/rfc6455#section-5.4
            raise WebSocketError, 'Received an unexpected continuation frame (uninitialized buffer)' if buffer_type.nil?

            buffer << frame.payload_data
          when Opcode::BINARY
            raise WebSocketError, 'Received an unexpected binary frame (incomplete buffer)' unless buffer_type.nil?

            buffer = frame.payload_data
            buffer_type = :binary
          when Opcode::TEXT
            raise WebSocketError, 'Received an unexpected text frame (incomplete buffer)' unless buffer_type.nil?

            buffer = frame.payload_data
            buffer_type = :text
          when Opcode::PING
            # see: https://datatracker.ietf.org/doc/html/rfc6455#section-5.5.2
            put_wsframe(frame.dup.tap { |f| f.header.opcode = Opcode::PONG }, opts = opts)
          end

          next unless frame.header.fin == 1

          if block_given?
            # text data is UTF-8 encoded
            # see: https://datatracker.ietf.org/doc/html/rfc6455#section-5.6
            buffer.force_encoding('UTF-8') if buffer_type == :text
            # release the stream lock before entering the callback, allowing it to close the socket if desired
            @wsstream_lock.unlock_read
            begin
              block.call(buffer, buffer_type)
            ensure
              @wsstream_lock.lock_read
            end
          end

          buffer = ''
          buffer_type = nil
        end
      end

      close
    end

    def close
      # if #wsloop was ever called, a synchronization lock will have been initialized
      @wsstream_lock.lock_write unless @wsstream_lock.nil?
      begin
        super
      ensure
        @wsstream_lock.unlock_write unless @wsstream_lock.nil?
      end
    end
  end

  class Opcode < BinData::Bit4
    CONTINUATION = 0
    TEXT = 1
    BINARY = 2
    CONNECTION_CLOSE = 8
    PING = 9
    PONG = 10

    default_parameter assert: -> { !Opcode.name(value).nil? }

    def self.name(value)
      constants.select { |c| c.upcase == c }.find { |c| const_get(c) == value }
    end

    def to_sym
      self.class.name(value)
    end
  end

  class Frame < BinData::Record
    endian :big

    struct :header do
      endian :big
      hide   :rsv1, :rsv2, :rsv3

      bit1   :fin, initial_value: 1
      bit1   :rsv1
      bit1   :rsv2
      bit1   :rsv3
      opcode :opcode
      bit1   :masked
      bit7   :payload_len_sm
      uint16 :payload_len_md, onlyif: -> { payload_len_sm == 126 }
      uint64 :payload_len_lg, onlyif: -> { payload_len_sm == 127 }
      uint32 :masking_key, onlyif: -> { masked == 1 }
    end
    string :payload_data, read_length: -> { payload_len }

    class << self
      private

      def from_opcode(opcode, payload, last: true, mask: true)
        frame = Frame.new(header: { fin: (last ? 1 : 0), opcode: opcode })
        frame.payload_len = payload.length
        frame.payload_data = payload

        case mask
        when TrueClass
          frame.mask!
        when Integer
          frame.mask!(mask)
        when FalseClass
        else
          raise ArgumentError, 'mask must be true, false or an integer (literal masking key)'
        end

        frame
      end
    end

    def self.apply_masking_key(data, mask)
      mask = [mask].pack('N').each_byte.to_a
      xored = ''
      data.each_byte.each_with_index do |byte, index|
        xored << (byte ^ mask[index % 4]).chr
      end

      xored
    end

    def self.from_binary(value, last: true, mask: true)
      from_opcode(Opcode::BINARY, value, last: last, mask: mask)
    end

    def self.from_text(value, last: true, mask: true)
      from_opcode(Opcode::TEXT, value, last: last, mask: mask)
    end

    #
    # Update the frame instance in place to apply a masking key to the payload data as defined in RFC 6455 section 5.3.
    #
    # @param [nil, Integer] key either an explicit 32-bit masking key or nil to generate a random one
    # @return [String] the masked payload data is returned
    def mask!(key = nil)
      header.masked.assign(1)
      key = rand(1..0xffffffff) if key.nil?
      header.masking_key.assign(key)
      payload_data.assign(self.class.apply_masking_key(payload_data, header.masking_key))
      payload_data.value
    end

    #
    # Update the frame instance in place to apply a masking key to the payload data as defined in RFC 6455 section 5.3.
    #
    # @return [String] the unmasked payload data is returned
    def unmask!
      payload_data.assign(self.class.apply_masking_key(payload_data, header.masking_key))
      header.masked.assign(0)
      payload_data.value
    end

    def payload_len
      case header.payload_len_sm
      when 127
        header.payload_len_lg
      when 126
        header.payload_len_md
      else
        header.payload_len_sm
      end
    end

    def payload_len=(value)
      if value < 126
        header.payload_len_sm.assign(value)
      elsif value < 0xffff
        header.payload_len_sm.assign(126)
        header.payload_len_md.assign(value)
      elsif value < 0x7fffffffffffffff
        header.payload_len_sm.assign(127)
        header.payload_len_lg.assign(value)
      else
        raise ArgumentError, 'payload length is outside the acceptable range'
      end
    end
  end
end
