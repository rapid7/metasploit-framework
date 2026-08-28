# -*- coding: binary -*-

require 'bindata'
# BinData resolves field types when a record's class body is evaluated, so the
# library types have to be registered before the records below are defined.
# Under Zeitwerk they would otherwise not load until first referenced.
require 'rex/proto/opc_ua/types'

# The OPC-UA TCP transport that carries opc.tcp:// (OPC-UA Specification Part 6,
# section 7). This is the framing layer only: it says what a message looks like
# and how a service response is put back together from chunks, and knows nothing
# about the services carried inside one.
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
  # RequestId ahead of its slice of the service payload.
  SECURE_MSG_PREFIX_LEN = 16

  # Defensive ceilings. A malformed or hostile response must fail quickly rather
  # than allocate without bound. Both values are carried over unchanged from the
  # module this library was factored out of.
  MAX_MESSAGE_SIZE = 4 * 1024 * 1024
  MAX_CHUNKS = 64

  # MessageType values, each three ASCII bytes. These are the types this
  # transport exchanges; every one of them appears in the captures under
  # spec/file_fixtures/opc_ua or is sent to produce them.
  module MessageType
    HELLO = 'HEL'.freeze
    ACKNOWLEDGE = 'ACK'.freeze
    ERROR = 'ERR'.freeze
    OPEN_SECURE_CHANNEL = 'OPN'.freeze
    CLOSE_SECURE_CHANNEL = 'CLO'.freeze
    MESSAGE = 'MSG'.freeze
  end

  # ChunkType values, one ASCII byte. A message that fits in one chunk is sent
  # as a single F.
  module ChunkType
    # More chunks follow this one.
    INTERMEDIATE = 'C'.freeze
    # The last chunk of the message.
    FINAL = 'F'.freeze
    # The server has abandoned the message; nothing further will follow.
    ABORT = 'A'.freeze
  end

  # The 8 byte header every message opens with.
  class MessageHeader < BinData::Record
    endian :little

    string :message_type, length: 3
    string :chunk_type, length: 1
    uint32 :message_size
  end

  # The Hello a client opens the connection with (Part 6, section 7.1.2). The
  # buffer sizes are what the client is willing to receive; a zero
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

  # The server's answer to a Hello (Part 6, section 7.1.2), carrying the same
  # five fields from the server's side. The buffer sizes it returns are the ones
  # that then govern the connection.
  class AcknowledgeMessage < BinData::Record
    endian :little

    uint32 :protocol_version
    uint32 :receive_buffer_size
    uint32 :send_buffer_size
    uint32 :max_message_size
    uint32 :max_chunk_count
  end

  # The body of an ERR message (Part 6, section 7.1.2): a StatusCode and a
  # Reason string, which servers routinely leave null.
  class ErrorMessage < BinData::Record
    endian :little

    uint32        :status_code
    opc_ua_string :reason
  end

  # One framed message as it came off the wire. The body excludes the header.
  Message = Struct.new(:message_type, :chunk_type, :body) do
    def error?
      message_type == MessageType::ERROR
    end

    def abort?
      chunk_type == ChunkType::ABORT
    end

    def final?
      chunk_type == ChunkType::FINAL
    end

    def intermediate?
      chunk_type == ChunkType::INTERMEDIATE
    end
  end

  # Frames and reassembles OPC-UA TCP messages over a socket.
  #
  # The only thing required of the socket is get_once(length, timeout), which is
  # what makes this testable without a network: Msf::Exploit::Remote::Tcp#sock
  # satisfies it and so does a test double. Writing is deliberately not part of
  # this class, since building a request is the business of the layer above.
  class MessageStream
    # Seconds allowed per read when the caller gives no timeout of its own.
    DEFAULT_TIMEOUT = 5

    # @return [Integer, Float] seconds allowed for satisfying one read. The
    #   header and the body of a message are each read under a fresh deadline.
    attr_reader :timeout

    # @param sock [#get_once] the socket to read from.
    # @param timeout [Integer, Float] seconds allowed per read.
    def initialize(sock, timeout: DEFAULT_TIMEOUT)
      @sock = sock
      @timeout = timeout
    end

    # Read exactly len bytes, accumulating across reads. A single read is not
    # guaranteed to return the full amount, and a GetEndpoints response carrying
    # server certificates routinely spans several segments.
    #
    # The deadline is monotonic rather than wall clock, so that a clock step
    # part way through a read cannot either cut it short or extend it
    # indefinitely.
    #
    # @param len [Integer] the number of bytes to read.
    # @return [String] exactly len bytes.
    # @raise [Error::TimeoutError] if the bytes did not arrive in time.
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
    # @raise [Error::TimeoutError] if the message did not arrive in time.
    # @raise [Error::FramingError] if the declared size is unusable.
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
    # @return [String] the reassembled service payload.
    # @raise [Error::ServerError] if the server answered with ERR.
    # @raise [Error::AbortError] if the server abandoned the response.
    # @raise [Error::FramingError] if the framing is unusable or the response
    #   ran past the chunk ceiling.
    # @raise [Error::TimeoutError] if a chunk did not arrive in time.
    def recv_service_response
      payload = ''.b

      MAX_CHUNKS.times do
        msg = recv_message
        raise server_error(msg.body) if msg.error?

        unless msg.message_type == MessageType::MESSAGE
          raise Error::FramingError, "unexpected message type #{msg.message_type.inspect}"
        end
        raise Error::AbortError, 'server aborted the response' if msg.abort?
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
    # An ERR arrives only once the server has decided the connection is
    # unusable, so a body that will not decode is still reported as the failure
    # it is rather than being replaced by a complaint about the decode; the
    # StatusCode is simply left unknown.
    #
    # @param body [String] the ERR message body.
    # @return [Error::ServerError]
    def server_error(body)
      err = ErrorMessage.read(body)
      Error::ServerError.new(status_code: err.status_code.snapshot, reason: err.reason.snapshot)
    rescue ::IOError, ::BinData::Error
      Error::ServerError.new
    end
  end
end
