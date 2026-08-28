# -*- coding: binary -*-
# frozen_string_literal: true

require 'bindata'
# BinData resolves field types when a record's class body is evaluated, so the
# library types have to be registered before the records below are defined.
# Under Zeitwerk they would otherwise not load until first referenced.
require 'rex/proto/opc_ua/types'

# The OPC-UA TCP transport that carries opc.tcp://. This is the framing layer
# only: it says what a message looks like and how a service response is put back
# together from chunks, and knows nothing about the services carried inside one.
#
# See OPC-UA Specification Part 6, section 7.1, the UA Connection Protocol,
# which defines the message header and the Hello, Acknowledge and Error messages
# below, and section 6.7 for the chunking MessageStream reassembles.
#
# Unlike the service structures elsewhere in this library, none of this framing
# appears in reference/opcua/Opc.Ua.Types.bsd: the schema describes the types
# services exchange, not the transport that carries them. The records here were
# therefore checked against the captures under spec/file_fixtures/opc_ua and
# against the reader in the module this library replaces, not against the
# schema.
module Rex::Proto::OpcUa::Tcp
  # Shorthand for the sibling error namespace. The compact module definition
  # above puts only this module in lexical scope, so without it every raise site
  # would have to name Rex::Proto::OpcUa::Error in full.
  Error = Rex::Proto::OpcUa::Error

  # Every message begins with an 8 byte header: MessageType (3 bytes ASCII),
  # ChunkType (1 byte ASCII) and MessageSize (UInt32 LE). MessageSize is the
  # total length of the message including the header itself.
  HEADER_LEN = 8

  # Each MSG chunk repeats SecureChannelId, TokenId, SequenceNumber and
  # RequestId ahead of its slice of the service payload. See
  # Rex::Proto::OpcUa::SecureChannel::SymmetricSecurityHeader, whose spec
  # asserts that those structures add up to this.
  SECURE_MSG_PREFIX_LEN = 16

  # Defensive ceilings. A malformed or hostile response must fail quickly rather
  # than allocate without bound. Both values are carried over unchanged from the
  # module this library was factored out of.
  MAX_MESSAGE_SIZE = 4 * 1024 * 1024
  MAX_CHUNKS = 64

  # MessageType values, each three ASCII bytes. These come from two layers, and
  # the specification keeps them in two places:
  #
  #   HEL, ACK and ERR belong to the Connection Protocol and are listed in
  #   Table 73 of OPC-UA Specification Part 6, section 7.1.2.2, alongside the
  #   RHE this library does not use.
  #
  #   MSG, OPN and CLO belong to the Secure Conversation layer and are listed in
  #   Table 57 of section 6.7.2.2. Table 73 accounts for them only as the
  #   additional values the Connection Protocol layer shall accept.
  #
  # Every one of the six appears in the captures under spec/file_fixtures/opc_ua
  # or is sent to produce them.
  module MessageType
    HELLO = 'HEL'
    ACKNOWLEDGE = 'ACK'
    ERROR = 'ERR'
    OPEN_SECURE_CHANNEL = 'OPN'
    CLOSE_SECURE_CHANNEL = 'CLO'
    MESSAGE = 'MSG'
  end

  # ChunkType values, one ASCII byte. This is the IsFinal field of Table 57 in
  # OPC-UA Specification Part 6, section 6.7.2.2, which notes that it is only
  # meaningful for a MessageType of MSG and is always F for the others. Part 6
  # calls the same byte Reserved at the Connection Protocol layer, in Table 73
  # of section 7.1.2.2, where it is likewise always F.
  #
  # A message that fits in one chunk is sent as a single F.
  module ChunkType
    # More chunks follow this one.
    INTERMEDIATE = 'C'
    # The last chunk of the message.
    FINAL = 'F'
    # The server has abandoned the message; nothing further will follow.
    ABORT = 'A'
  end

  # The 8 byte header every message opens with. See OPC-UA Specification
  # Part 6, section 7.1.2.2.
  class MessageHeader < BinData::Record
    endian :little

    string :message_type, length: 3
    string :chunk_type, length: 1
    uint32 :message_size
  end

  # The Hello a client opens the connection with. See OPC-UA Specification
  # Part 6, section 7.1.2.3.
  #
  # The buffer sizes are what the client is willing to receive; a zero
  # MaxMessageSize or MaxChunkCount means the client sets no limit of its own,
  # which is not the same as accepting anything, since MessageStream applies its
  # own ceilings regardless.
  class HelloMessage < BinData::Record
    endian :little

    uint32        :protocol_version
    uint32        :receive_buffer_size
    uint32        :send_buffer_size
    uint32        :max_message_size
    uint32        :max_chunk_count
    opc_ua_string :endpoint_url
  end

  # The server's answer to a Hello, carrying the same five fields from the
  # server's side. See OPC-UA Specification Part 6, section 7.1.2.4. The buffer
  # sizes it returns are the ones that then govern the connection.
  class AcknowledgeMessage < BinData::Record
    endian :little

    uint32 :protocol_version
    uint32 :receive_buffer_size
    uint32 :send_buffer_size
    uint32 :max_message_size
    uint32 :max_chunk_count
  end

  # The body of an ERR message: a StatusCode and a Reason string, which servers
  # routinely leave null. See OPC-UA Specification Part 6, section 7.1.2.5; the
  # StatusCode itself is section 5.2.2.11, and the values are named in
  # Rex::Proto::OpcUa::Enums::STATUS_CODES.
  class ErrorMessage < BinData::Record
    endian :little

    uint32        :status_code
    opc_ua_string :reason

    # Decode a body that arrives only once the server has decided it cannot
    # answer, so it is read as leniently as it can be: the two fields are taken
    # one at a time, and a Reason that will not decode still leaves the
    # StatusCode reportable. An ERR is the server's only account of why it gave
    # up, and half of one is worth more than none.
    #
    # @param body [String] the two fields, without any framing.
    # @return [Array(Integer, String), Array(Integer, nil), Array(nil, nil)] the
    #   StatusCode and Reason, either of which is nil when it could not be read.
    def self.decode(body)
      raw = body.to_s.b
      return [nil, nil] if raw.bytesize < 4

      reason = begin
        Rex::Proto::OpcUa::Types::OpcUaString.read(raw.byteslice(4..-1).to_s).snapshot
      rescue ::IOError, ::BinData::ValidityError
        nil
      end

      [raw.byteslice(0, 4).unpack1('V'), reason]
    end
  end

  # One framed message as it came off the wire. The body excludes the header.
  Message = Struct.new(:message_type, :chunk_type, :body) do
    # @return [Boolean] whether this is an ERR message, which a server sends in
    #   place of the response that was asked for.
    def error?
      message_type == MessageType::ERROR
    end

    # @return [Boolean] whether this chunk abandons the message it belongs to.
    def abort?
      chunk_type == ChunkType::ABORT
    end

    # @return [Boolean] whether this is the last chunk of its message.
    def final?
      chunk_type == ChunkType::FINAL
    end

    # @return [Boolean] whether another chunk follows this one.
    def intermediate?
      chunk_type == ChunkType::INTERMEDIATE
    end
  end

  # Frames and reassembles OPC-UA TCP messages over a socket.
  #
  # The only thing required of the socket is get_once(length, timeout) and put,
  # which is what makes this testable without a network:
  # Msf::Exploit::Remote::Tcp#sock satisfies it and so does a test double.
  #
  # Building the body of a request belongs to the layer above; what belongs here
  # is the header that wraps it, so that a caller cannot get MessageSize wrong.
  class MessageStream
    # Seconds allowed per read when the caller gives no timeout of its own.
    DEFAULT_TIMEOUT = 5

    # @return [Integer, Float] seconds allowed for satisfying one read. The
    #   header and the body of a message are each read under a fresh deadline.
    attr_reader :timeout

    # @param sock [#get_once] the socket to read from. Only
    #   get_once(length, timeout) is called on it.
    # @param timeout [Integer, Float] seconds allowed per read.
    # @return [MessageStream]
    def initialize(sock, timeout: DEFAULT_TIMEOUT)
      @sock = sock
      @timeout = timeout
    end

    # Frame a message and write it. MessageSize counts the header, so it is
    # computed here rather than trusted from the caller.
    #
    # Nothing this library sends needs more than one chunk: a Hello, an
    # OpenSecureChannel and a GetEndpoints request are all small, and the
    # SendBufferSize a server may impose is at least 8192 bytes.
    #
    # @param message_type [String] a MessageType value.
    # @param body [String] everything that follows the 8 byte header.
    # @param chunk_type [String] a ChunkType value.
    # @return [Integer] the number of bytes written.
    def send_message(message_type, body, chunk_type: ChunkType::FINAL)
      raw = body.to_s.b
      @sock.put((message_type + chunk_type).b + [HEADER_LEN + raw.bytesize].pack('V') + raw)
    end

    # Read exactly len bytes, accumulating across reads. A single read is not
    # guaranteed to return the full amount, and a GetEndpoints response carrying
    # server certificates routinely spans several segments.
    #
    # The deadline is monotonic rather than wall clock, so that a clock step
    # part way through a read cannot either cut it short or extend it
    # indefinitely. Rex::Stopwatch.elapsed_time measures a completed block
    # rather than exposing a remaining budget, so it does not fit a loop that
    # has to shorten each successive read.
    #
    # @param len [Integer] the number of bytes to read. Zero or fewer reads
    #   nothing.
    # @return [String] exactly len bytes, binary encoded.
    # @raise [Rex::Proto::OpcUa::Error::TimeoutError] if the bytes did not
    #   arrive in time.
    def read_exact(len)
      return ''.b unless len.positive?

      buf = ''.b
      deadline = ::Process.clock_gettime(::Process::CLOCK_MONOTONIC) + timeout
      while buf.bytesize < len
        left = deadline - ::Process.clock_gettime(::Process::CLOCK_MONOTONIC)
        unless left.positive?
          raise Error::TimeoutError, "read of #{len} bytes timed out after #{timeout}s with #{buf.bytesize} read"
        end

        # A Rex socket returns nil from get_once when nothing arrived before the
        # timeout, and raises EOFError when the peer closed the connection. Only
        # the first of those is ours to translate; a close is left to propagate
        # as itself.
        chunk = @sock.get_once(len - buf.bytesize, left)
        if chunk.nil? || chunk.empty?
          raise Error::TimeoutError, "read of #{len} bytes returned no data with #{buf.bytesize} read"
        end

        buf << chunk.b
      end

      buf
    end

    # Read one framed message.
    #
    # @return [Message] the message type, chunk type and body.
    # @raise [Rex::Proto::OpcUa::Error::TimeoutError] if the message did not
    #   arrive in time.
    # @raise [Rex::Proto::OpcUa::Error::FramingError] if the declared size is
    #   unusable.
    def recv_message
      header = MessageHeader.read(read_exact(HEADER_LEN))
      size = header.message_size.snapshot
      if size < HEADER_LEN || size > MAX_MESSAGE_SIZE
        raise Error::FramingError, "message size #{size} outside #{HEADER_LEN}..#{MAX_MESSAGE_SIZE}"
      end

      Message.new(
        header.message_type.snapshot,
        header.chunk_type.snapshot,
        read_exact(size - HEADER_LEN)
      )
    end

    # Read a complete service response, reassembling it where the server split
    # it across chunks. Continuation chunks repeat the SecureChannelId, TokenId
    # and SequenceHeader ahead of their payload slice, so those bytes are
    # stripped before concatenation. The returned buffer therefore starts at the
    # response TypeId, not at the SecureChannelId.
    #
    # @return [String] the reassembled service payload, binary encoded.
    # @raise [Rex::Proto::OpcUa::Error::ServerError] if the server answered with
    #   ERR.
    # @raise [Rex::Proto::OpcUa::Error::AbortError] if the server abandoned the
    #   response.
    # @raise [Rex::Proto::OpcUa::Error::FramingError] if the framing is unusable
    #   or the response ran past the chunk ceiling.
    # @raise [Rex::Proto::OpcUa::Error::TimeoutError] if a chunk did not arrive
    #   in time.
    def recv_service_response
      payload = ''.b

      MAX_CHUNKS.times do
        msg = recv_message
        raise server_error(msg.body) if msg.error?

        unless msg.message_type == MessageType::MESSAGE
          raise Error::FramingError, "unexpected message type #{msg.message_type.inspect}"
        end
        raise abort_error(msg.body) if msg.abort?
        raise Error::FramingError, "unknown chunk type #{msg.chunk_type.inspect}" unless msg.final? || msg.intermediate?

        if msg.body.bytesize < SECURE_MSG_PREFIX_LEN
          raise Error::FramingError,
                "chunk of #{msg.body.bytesize} bytes is shorter than its #{SECURE_MSG_PREFIX_LEN} byte header"
        end

        payload << msg.body.byteslice(SECURE_MSG_PREFIX_LEN..-1)
        return payload if msg.final?
      end

      raise Error::FramingError, "response exceeded the #{MAX_CHUNKS} chunk ceiling"
    end

    private

    # Build the exception for an ERR message.
    #
    # @param body [String] the ERR message body.
    # @return [Rex::Proto::OpcUa::Error::ServerError]
    def server_error(body)
      Error::ServerError.new(**status_and_reason(body))
    end

    # Build the exception for an aborted response.
    #
    # An abort chunk is a MSG chunk, so its body opens with the secure
    # conversation prefix and the Table 63 fields follow it. A chunk too short
    # to hold even that prefix still aborts the response, so the slice is taken
    # defensively rather than guarded by the length check that the ordinary
    # chunk path applies further down.
    #
    # @param body [String] the abort chunk body, prefix included.
    # @return [Rex::Proto::OpcUa::Error::AbortError]
    def abort_error(body)
      Error::AbortError.new(**status_and_reason(body.byteslice(SECURE_MSG_PREFIX_LEN..-1).to_s))
    end

    # The StatusCode and Reason that an ERR body and an abort body both carry, in
    # the same two fields in the same order.
    #
    # @param body [String] the bytes of the two fields.
    # @return [Hash] keyword arguments for the exception.
    def status_and_reason(body)
      status_code, reason = ErrorMessage.decode(body)

      { status_code: status_code, reason: reason }
    end
  end
end
