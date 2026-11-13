# -*- coding: binary -*-

require 'spec_helper'
# BinData resolves field types when a record's class body is evaluated, so the
# transport records have to be registered before the examples reference them.
# Under Zeitwerk they would otherwise not load until first referenced.
require 'rex/proto/opc_ua/tcp'

# A stand-in for a Rex socket. MessageStream asks nothing of its socket but
# get_once(length, timeout), so that is all this provides. Defined at the top
# level because a class defined inside a describe block is defined on Object
# anyway; the OpcUaSpec prefix keeps it from colliding with anything.
class OpcUaSpecSocket
  # @param data [String] the bytes to hand out.
  # @param segment [Integer, nil] the most bytes to return from a single read,
  #   so that a response can be split the way a real network splits one.
  def initialize(data, segment: nil)
    @data = data.dup.b
    @segment = segment
  end

  # @return [String, nil] nil once the bytes run out, which is what a Rex socket
  #   returns when nothing arrived before its timeout.
  def get_once(length, _timeout)
    return nil if @data.empty?

    @data.slice!(0, @segment ? [length, @segment].min : length)
  end
end

# A socket that answers every read by consuming the whole timeout it was given
# and then returning a single byte. A caller that reads under a deadline makes
# no progress against it and must give up rather than read forever.
class OpcUaSpecStallingSocket
  # @return [Integer] how many reads have been served.
  attr_reader :reads

  def initialize
    @reads = 0
  end

  def get_once(_length, timeout)
    @reads += 1
    sleep(timeout)
    "\x00".b
  end
end

RSpec.describe 'Rex::Proto::OpcUa TCP transport' do
  # The single captured ACK, whole and including its 8 byte message header. See
  # spec/file_fixtures/opc_ua/README.md for provenance.
  let(:ack) { File.binread(File.join(FILE_FIXTURES_PATH, 'opc_ua', 'ack_node_opcua.bin')) }

  # No capture contains a chunked response - every message under
  # spec/file_fixtures/opc_ua is a single F chunk - so the multi-chunk frames
  # below are hand-built from the framing given in OPC-UA Specification Part 6
  # rather than taken from the wire. That is deliberate and is recorded under
  # Coverage limits in spec/file_fixtures/opc_ua/README.md.
  def frame(message_type, chunk_type, body)
    (message_type + chunk_type).b + [Rex::Proto::OpcUa::Tcp::HEADER_LEN + body.bytesize].pack('V') + body
  end

  # A MSG chunk: the secure conversation prefix (SecureChannelId, TokenId,
  # SequenceNumber, RequestId) followed by this chunk's slice of the payload.
  # The prefix values are arbitrary; only their length matters to the framing.
  def msg_chunk(chunk_type, payload, sequence: 1)
    frame('MSG', chunk_type, [0x2A, 0x01, sequence, 0x07].pack('V4') + payload)
  end

  # An ERR message: StatusCode then a Reason string, null when reason is nil.
  # These two fields are Table 76 of Part 6 section 7.1.2.5.
  def err_frame(status_code, reason = nil)
    frame('ERR', 'F', status_and_reason(status_code, reason))
  end

  # The same two fields, which Table 63 of section 6.7.3 gives as the body of an
  # abort chunk. An abort is a MSG chunk, so they follow the secure conversation
  # prefix.
  def abort_chunk(status_code, reason = nil)
    msg_chunk('A', status_and_reason(status_code, reason))
  end

  def status_and_reason(status_code, reason)
    body = [status_code].pack('V')
    body << (reason.nil? ? [-1].pack('l<') : [reason.bytesize].pack('l<') + reason.b)
    body
  end

  describe 'ceilings' do
    # These are carried over unchanged from the module the library was factored
    # out of. Pinning them means a change to either is a deliberate one.
    it 'caps a single message at 4 MiB' do
      expect(Rex::Proto::OpcUa::Tcp::MAX_MESSAGE_SIZE).to eq 4 * 1024 * 1024
    end

    it 'caps a reassembled response at 64 chunks' do
      expect(Rex::Proto::OpcUa::Tcp::MAX_CHUNKS).to eq 64
    end
  end

  describe Rex::Proto::OpcUa::Tcp::MessageHeader do
    subject(:header) { described_class.read(ack) }

    it 'decodes the MessageType of the captured ACK' do
      expect(header.message_type.snapshot).to eq 'ACK'
    end

    it 'decodes the ChunkType of the captured ACK' do
      expect(header.chunk_type.snapshot).to eq 'F'
    end

    # MessageSize counts the header itself, so it is the whole capture.
    it 'decodes a MessageSize that covers the whole message' do
      expect(header.message_size.snapshot).to eq ack.bytesize
    end

    it 'consumes exactly the header length' do
      expect(header.num_bytes).to eq Rex::Proto::OpcUa::Tcp::HEADER_LEN
    end

    it 're-encodes to the captured bytes' do
      expect(header.to_binary_s).to eq ack.byteslice(0, 8)
    end
  end

  describe Rex::Proto::OpcUa::Tcp::AcknowledgeMessage do
    # The body follows the 8 byte message header.
    subject(:acknowledge) { described_class.read(ack[8..]) }

    it 'decodes the ProtocolVersion' do
      expect(acknowledge.protocol_version.snapshot).to eq 0
    end

    it 'decodes the ReceiveBufferSize' do
      expect(acknowledge.receive_buffer_size.snapshot).to eq 65_535
    end

    it 'decodes the SendBufferSize' do
      expect(acknowledge.send_buffer_size.snapshot).to eq 65_535
    end

    it 'decodes the MaxMessageSize' do
      expect(acknowledge.max_message_size.snapshot).to eq 16_777_216
    end

    it 'decodes the MaxChunkCount' do
      expect(acknowledge.max_chunk_count.snapshot).to eq 256
    end

    # Five UInt32 fields and nothing else. Checking that the record accounts for
    # the capture exactly is what proves no field was skipped or double counted,
    # since five wrong offsets can still each decode to some number.
    it 'accounts for the whole captured body' do
      expect(acknowledge.num_bytes).to eq ack.bytesize - Rex::Proto::OpcUa::Tcp::HEADER_LEN
    end

    it 're-encodes to the captured bytes' do
      expect(acknowledge.to_binary_s).to eq ack[8..]
    end
  end

  describe Rex::Proto::OpcUa::Tcp::HelloMessage do
    # The captures are server responses, so there is no captured client Hello to
    # test against; this covers the field order and the length prefixed
    # EndpointUrl by round trip instead.
    subject(:hello) do
      described_class.new(
        protocol_version: 0,
        receive_buffer_size: 65_535,
        send_buffer_size: 65_535,
        max_message_size: 0,
        max_chunk_count: 0,
        endpoint_url: 'opc.tcp://192.0.2.1:4840'
      )
    end

    it 'encodes the five UInt32 fields ahead of the EndpointUrl' do
      expect(hello.to_binary_s.byteslice(0, 20)).to eq [0, 65_535, 65_535, 0, 0].pack('V5')
    end

    it 'encodes the EndpointUrl with its length prefix' do
      url = 'opc.tcp://192.0.2.1:4840'
      expect(hello.to_binary_s.byteslice(20..)).to eq [url.bytesize].pack('l<') + url
    end

    it 'round trips' do
      expect(described_class.read(hello.to_binary_s).snapshot).to eq hello.snapshot
    end
  end

  describe Rex::Proto::OpcUa::Tcp::ErrorMessage do
    it 'decodes the StatusCode' do
      body = err_frame(0x807D0000, 'too busy')[8..]
      expect(described_class.read(body).status_code.snapshot).to eq 0x807D0000
    end

    it 'decodes the Reason' do
      body = err_frame(0x807D0000, 'too busy')[8..]
      expect(described_class.read(body).reason.snapshot).to eq 'too busy'
    end

    # Servers routinely send ERR with no Reason at all, which is a null String
    # rather than an empty one.
    it 'decodes a null Reason as nil' do
      body = err_frame(0x80820000)[8..]
      expect(described_class.read(body).reason.snapshot).to be_nil
    end
  end

  describe Rex::Proto::OpcUa::Tcp::MessageStream do
    # Short enough that the examples covering the deadline do not stall the
    # suite, long enough that the examples reading from memory never reach it.
    let(:timeout) { 0.5 }

    def stream_over(data, segment: nil)
      described_class.new(OpcUaSpecSocket.new(data, segment: segment), timeout: timeout)
    end

    describe '#read_exact' do
      it 'returns exactly the requested bytes and leaves the rest' do
        stream = stream_over('abcdefgh')
        expect(stream.read_exact(3)).to eq 'abc'
        expect(stream.read_exact(5)).to eq 'defgh'
      end

      # The reason read_exact exists at all: one read is not one message.
      it 'accumulates across reads that return less than was asked for' do
        expect(stream_over('abcdefgh', segment: 1).read_exact(8)).to eq 'abcdefgh'
      end

      it 'returns binary encoded bytes' do
        expect(stream_over('abc').read_exact(3).encoding).to eq ::Encoding::BINARY
      end

      it 'reads nothing when asked for nothing' do
        expect(stream_over('abc').read_exact(0)).to eq ''
      end

      it 'raises when the peer sends nothing at all' do
        expect { stream_over('').read_exact(4) }
          .to raise_error(Rex::Proto::OpcUa::Error::TimeoutError, /returned no data with 0 read/)
      end

      it 'raises when the peer stops part way through and reports how far it got' do
        expect { stream_over('ab').read_exact(4) }
          .to raise_error(Rex::Proto::OpcUa::Error::TimeoutError, /returned no data with 2 read/)
      end

      # A peer that dribbles out bytes slowly enough would otherwise hold the
      # read open indefinitely, since every individual read makes progress.
      it 'gives up once the deadline has passed even while bytes are arriving' do
        socket = OpcUaSpecStallingSocket.new
        stream = described_class.new(socket, timeout: 0.05)

        expect { stream.read_exact(4) }
          .to raise_error(Rex::Proto::OpcUa::Error::TimeoutError, /timed out after 0.05s with 1 read/)
        expect(socket.reads).to eq 1
      end
    end

    describe '#recv_message' do
      subject(:message) { stream_over(ack).recv_message }

      it 'returns the MessageType of the captured ACK' do
        expect(message.message_type).to eq 'ACK'
      end

      it 'returns the ChunkType of the captured ACK' do
        expect(message.chunk_type).to eq 'F'
      end

      it 'returns the body with the header removed' do
        expect(message.body).to eq ack[8..]
      end

      it 'reassembles a message split across reads' do
        expect(stream_over(ack, segment: 3).recv_message.body).to eq ack[8..]
      end

      # A MessageSize below the header length would make the body length
      # negative; there is no message this can describe.
      it 'rejects a MessageSize smaller than the header' do
        expect { stream_over("MSGF\x07\x00\x00\x00".b).recv_message }
          .to raise_error(Rex::Proto::OpcUa::Error::FramingError, /message size 7 outside/)
      end

      # The ceiling matters most here: the size is believed only far enough to
      # reject it, so nothing is allocated on the strength of it. Before a size
      # has been negotiated the bound is MAX_CHUNK_SIZE.
      it 'rejects a MessageSize above the ceiling' do
        oversize = 'MSGF'.b + [Rex::Proto::OpcUa::Tcp::MAX_CHUNK_SIZE + 1].pack('V')

        expect { stream_over(oversize).recv_message }
          .to raise_error(Rex::Proto::OpcUa::Error::FramingError, /message size 4194305 outside/)
      end
    end

    describe '#recv_service_response' do
      it 'returns the payload of a single final chunk' do
        expect(stream_over(msg_chunk('F', 'service-payload')).recv_service_response).to eq 'service-payload'
      end

      it 'strips the secure conversation prefix from the payload it returns' do
        expect(stream_over(msg_chunk('F', 'service-payload')).recv_service_response.bytesize).to eq 15
      end

      it 'reassembles a response split across continuation chunks' do
        data = msg_chunk('C', 'one-', sequence: 1) +
               msg_chunk('C', 'two-', sequence: 2) +
               msg_chunk('F', 'three', sequence: 3)

        expect(stream_over(data).recv_service_response).to eq 'one-two-three'
      end

      # Chunk reassembly and read accumulation are separate concerns and a
      # server that chunks a response is exactly the one likely to trip both.
      it 'reassembles chunks that are themselves split across reads' do
        data = msg_chunk('C', 'one-') + msg_chunk('F', 'two')

        expect(stream_over(data, segment: 2).recv_service_response).to eq 'one-two'
      end

      it 'stops at the final chunk and leaves anything after it unread' do
        stream = stream_over(msg_chunk('F', 'first') + msg_chunk('F', 'second'))

        expect(stream.recv_service_response).to eq 'first'
        expect(stream.recv_service_response).to eq 'second'
      end

      it 'raises when the server aborts part way through' do
        data = msg_chunk('C', 'one-') + abort_chunk(0x80840000)

        expect { stream_over(data).recv_service_response }
          .to raise_error(Rex::Proto::OpcUa::Error::AbortError, /aborted/)
      end

      # An abort chunk says why it aborted, in the same two fields an ERR
      # carries. Discarding them would throw away the only account of what went
      # wrong that the server is going to give.
      it 'carries the StatusCode and Reason from the abort chunk' do
        data = msg_chunk('C', 'one-') + abort_chunk(0x80840000, 'client took too long')

        expect { stream_over(data).recv_service_response }
          .to raise_error(Rex::Proto::OpcUa::Error::AbortError) { |e|
            expect(e.status_code).to eq 0x80840000
            expect(e.reason).to eq 'client took too long'
            expect(e.message).to include 'Bad_RequestInterrupted'
          }
      end

      it 'carries a null Reason from the abort chunk as nil' do
        expect { stream_over(abort_chunk(0x80850000)).recv_service_response }
          .to raise_error(Rex::Proto::OpcUa::Error::AbortError) { |e|
            expect(e.reason).to be_nil
          }
      end

      # The abort still stands even when its own body is unusable: the response
      # is not coming either way, and a complaint about the abort body would
      # replace the more useful fact.
      it 'still aborts when the abort chunk is too short to hold its own body' do
        short = frame('MSG', 'A', 'x' * (Rex::Proto::OpcUa::Tcp::SECURE_MSG_PREFIX_LEN - 1))

        expect { stream_over(short).recv_service_response }
          .to raise_error(Rex::Proto::OpcUa::Error::AbortError) { |e|
            expect(e.status_code).to be_nil
          }
      end

      it 'still aborts when the abort body will not decode' do
        expect { stream_over(msg_chunk('A', "\x01\x02".b)).recv_service_response }
          .to raise_error(Rex::Proto::OpcUa::Error::AbortError) { |e|
            expect(e.status_code).to be_nil
          }
      end

      it 'raises when the server answers with ERR part way through' do
        data = msg_chunk('C', 'one-') + err_frame(0x80820000, 'internal error')

        expect { stream_over(data).recv_service_response }
          .to raise_error(Rex::Proto::OpcUa::Error::ServerError,
                          /server returned ERR: Bad_TcpInternalError - internal error/)
      end

      # ERR and abort share a base class and a message format, so the two have
      # to stay distinguishable by what they say as well as by their class.
      it 'distinguishes an ERR from an abort in the message' do
        expect { stream_over(err_frame(0x80820000)).recv_service_response }
          .to raise_error(Rex::Proto::OpcUa::Error::ServerError, /\Aserver returned ERR:/)
        expect { stream_over(abort_chunk(0x80820000)).recv_service_response }
          .to raise_error(Rex::Proto::OpcUa::Error::AbortError, /\Aserver aborted the response:/)
      end

      it 'carries the StatusCode from an ERR on the exception' do
        expect { stream_over(err_frame(0x807D0000)).recv_service_response }
          .to raise_error(Rex::Proto::OpcUa::Error::ServerError) { |e|
            expect(e.status_code).to eq 0x807D0000
            expect(e.reason).to be_nil
          }
      end

      # An ERR is a report that the server has given up on the connection, so a
      # body too short to decode is still reported as the failure it is.
      it 'still raises a ServerError when the ERR body will not decode' do
        expect { stream_over(frame('ERR', 'F', "\x01\x02".b)).recv_service_response }
          .to raise_error(Rex::Proto::OpcUa::Error::ServerError) { |e|
            expect(e.status_code).to be_nil
          }
      end

      # The prefix is stripped by length, so a chunk shorter than the prefix
      # would otherwise silently contribute nothing or slice past its own end.
      it 'raises on a chunk shorter than its own secure conversation prefix' do
        short = frame('MSG', 'F', 'x' * (Rex::Proto::OpcUa::Tcp::SECURE_MSG_PREFIX_LEN - 1))

        expect { stream_over(short).recv_service_response }
          .to raise_error(Rex::Proto::OpcUa::Error::FramingError, /15 bytes is shorter than its 16 byte header/)
      end

      it 'raises on a message that is not part of a service response' do
        expect { stream_over(frame('OPN', 'F', 'x' * 20)).recv_service_response }
          .to raise_error(Rex::Proto::OpcUa::Error::FramingError, /unexpected message type "OPN"/)
      end

      # C, F and A are the only chunk types the specification defines. Treating
      # anything else as a continuation would spend the whole chunk budget on a
      # frame already known to be malformed.
      it 'raises on a chunk type the specification does not define' do
        expect { stream_over(msg_chunk('X', 'payload')).recv_service_response }
          .to raise_error(Rex::Proto::OpcUa::Error::FramingError, /unknown chunk type "X"/)
      end

      # A server that never sends a final chunk must not be able to hold the
      # scanner open, whether by accident or deliberately.
      it 'raises once the chunk ceiling is reached with no final chunk' do
        data = msg_chunk('C', 'x') * Rex::Proto::OpcUa::Tcp::MAX_CHUNKS

        expect { stream_over(data).recv_service_response }
          .to raise_error(Rex::Proto::OpcUa::Error::FramingError, /exceeded the 64 chunk ceiling/)
      end

      it 'accepts a response that reaches the chunk ceiling exactly' do
        data = msg_chunk('C', 'x') * (Rex::Proto::OpcUa::Tcp::MAX_CHUNKS - 1) + msg_chunk('F', 'x')

        expect(stream_over(data).recv_service_response).to eq 'x' * Rex::Proto::OpcUa::Tcp::MAX_CHUNKS
      end

      it 'raises when a chunk never arrives' do
        expect { stream_over(msg_chunk('C', 'one-')).recv_service_response }
          .to raise_error(Rex::Proto::OpcUa::Error::TimeoutError)
      end
    end
  end
end

# The write side, kept in its own group both because it is a separate concern
# from framing what comes back and because the transport group above is already
# at the block length the project's RuboCop configuration allows.
RSpec.describe 'Rex::Proto::OpcUa::Tcp::MessageStream#send_message' do
  let(:written) { [] }

  let(:socket) do
    sink = written
    Class.new do
      define_method(:put) { |data| sink << data.dup.b }
      define_method(:get_once) { |_length, _timeout| nil }
    end.new
  end

  subject(:stream) { Rex::Proto::OpcUa::Tcp::MessageStream.new(socket, timeout: 0.5) }

  it 'writes the message type, a final chunk type and the body' do
    stream.send_message('HEL', 'body')

    expect(written.first.byteslice(0, 4)).to eq 'HELF'
    expect(written.first.byteslice(8..)).to eq 'body'
  end

  # MessageSize counts the header, so a caller that computed it would have to
  # know that. Getting it wrong desynchronizes the server for every request that
  # follows, which is why it is not the caller's to get wrong.
  it 'declares a MessageSize that includes the header' do
    stream.send_message('HEL', 'body')

    expect(written.first.byteslice(4, 4).unpack1('V')).to eq written.first.bytesize
    expect(written.first.bytesize).to eq Rex::Proto::OpcUa::Tcp::HEADER_LEN + 4
  end

  it 'frames an empty body' do
    stream.send_message('CLO', '')

    expect(written.first).to eq "CLOF\x08\x00\x00\x00".b
  end

  it 'takes a chunk type when one is given' do
    stream.send_message('MSG', '', chunk_type: 'C')

    expect(written.first.byteslice(0, 4)).to eq 'MSGC'
  end

  it 'writes binary regardless of the encoding it was handed' do
    stream.send_message('HEL', "caf\xC3\xA9")

    expect(written.first.encoding).to eq ::Encoding::BINARY
  end
end

# The lenient decode both an ERR message and an abort chunk go through. Kept out
# of the transport group above so that group stays within the block length the
# project's RuboCop configuration allows.
RSpec.describe Rex::Proto::OpcUa::Tcp::ErrorMessage do
  def body(status_code, reason = nil)
    raw = [status_code].pack('V')
    raw << (reason.nil? ? [-1].pack('l<') : [reason.bytesize].pack('l<') + reason.b)
    raw
  end

  describe '.decode' do
    it 'returns the StatusCode and Reason' do
      expect(described_class.decode(body(0x807D0000, 'busy'))).to eq [0x807D0000, 'busy']
    end

    it 'returns a null Reason as nil' do
      expect(described_class.decode(body(0x807D0000))).to eq [0x807D0000, nil]
    end

    it 'returns nothing at all when there is not even a StatusCode' do
      expect(described_class.decode("\x01\x02".b)).to eq [nil, nil]
      expect(described_class.decode('')).to eq [nil, nil]
    end

    # Half an ERR is worth more than none: the StatusCode is the part that says
    # why the server gave up, and it is readable even when the Reason is not.
    it 'keeps the StatusCode when the Reason will not decode' do
      truncated = [0x807D0000].pack('V') + [64].pack('l<') + 'short'

      expect(described_class.decode(truncated)).to eq [0x807D0000, nil]
    end

    it 'reads the fields the record reads' do
      raw = body(0x80820000, 'internal')
      record = described_class.read(raw)

      expect(described_class.decode(raw)).to eq [record.status_code.snapshot, record.reason.snapshot]
    end
  end
end

# The three ceilings are layered, and each of the specs above tests one of them
# on its own. These test them against each other, which is where the gap was:
# bounding one chunk and bounding the number of chunks says nothing about the
# size of what they add up to.
RSpec.describe 'Rex::Proto::OpcUa::Tcp::MessageStream bounds' do
  def frame(message_type, chunk_type, body)
    (message_type + chunk_type).b + [Rex::Proto::OpcUa::Tcp::HEADER_LEN + body.bytesize].pack('V') + body
  end

  def msg_chunk(chunk_type, payload)
    frame('MSG', chunk_type, [1, 2, 3, 4].pack('V4') + payload)
  end

  def stream_over(data)
    socket = Class.new do
      define_method(:initialize) { @buffer = data.dup.b }
      define_method(:get_once) { |length, _timeout| @buffer.empty? ? nil : @buffer.slice!(0, length) }
    end.new

    Rex::Proto::OpcUa::Tcp::MessageStream.new(socket, timeout: 0.5)
  end

  let(:hello) { Rex::Proto::OpcUa::Tcp::HelloMessage.new(receive_buffer_size: 65_535) }

  def acknowledge(send_buffer_size)
    Rex::Proto::OpcUa::Tcp::AcknowledgeMessage.new(
      receive_buffer_size: 65_535,
      send_buffer_size: send_buffer_size
    )
  end

  describe '#negotiate' do
    subject(:stream) { stream_over('') }

    it 'accepts MAX_CHUNK_SIZE until a size has been negotiated' do
      expect(stream.max_chunk_size).to eq Rex::Proto::OpcUa::Tcp::MAX_CHUNK_SIZE
    end

    it 'takes the chunk size the server said it would send' do
      expect(stream.negotiate(hello, acknowledge(16_384))).to eq 16_384
      expect(stream.max_chunk_size).to eq 16_384
    end

    # Part 6 Table 75 requires the server's SendBufferSize not to exceed the
    # ReceiveBufferSize the Hello asked for. A server that ignores that is not
    # believed: it cannot enlarge what this client agreed to receive.
    it 'never exceeds what the Hello asked to receive' do
      stream.negotiate(hello, acknowledge(1_000_000))

      expect(stream.max_chunk_size).to eq 65_535
    end

    # This is the guard that stops a server answering the Hello with a figure
    # that would put the per chunk bound back where it started.
    it 'refuses a chunk size larger than this library will ever accept' do
      oversize = acknowledge(Rex::Proto::OpcUa::Tcp::MAX_CHUNK_SIZE + 1)

      expect { stream.negotiate(hello, oversize) }
        .to raise_error(Rex::Proto::OpcUa::Error::FramingError, /SendBufferSize of 4194305, outside/)
    end

    it 'refuses a chunk size of zero, which no message could satisfy' do
      expect { stream.negotiate(hello, acknowledge(0)) }
        .to raise_error(Rex::Proto::OpcUa::Error::FramingError, /SendBufferSize of 0, outside/)
    end

    it 'leaves the bound alone when it refuses' do
      begin
        stream.negotiate(hello, acknowledge(0))
      rescue Rex::Proto::OpcUa::Error::FramingError
        nil
      end

      expect(stream.max_chunk_size).to eq Rex::Proto::OpcUa::Tcp::MAX_CHUNK_SIZE
    end

    # A server entitled to send smaller chunks than asked for is taken at its
    # word, since that can only make this client allocate less.
    it 'accepts a smaller chunk size than was asked for' do
      stream.negotiate(hello, acknowledge(8192))

      expect(stream.max_chunk_size).to eq 8192
    end
  end

  describe 'the negotiated chunk size' do
    it 'bounds a chunk that the unnegotiated ceiling would have allowed' do
      stream = stream_over('MSGF'.b + [70_000].pack('V'))
      stream.negotiate(hello, acknowledge(65_535))

      expect { stream.recv_message }
        .to raise_error(Rex::Proto::OpcUa::Error::FramingError, /message size 70000 outside 8..65535/)
    end

    it 'admits a chunk that fits inside it' do
      body = [1, 2, 3, 4].pack('V4') + 'payload'
      stream = stream_over(frame('MSG', 'F', body))
      stream.negotiate(hello, acknowledge(65_535))

      expect(stream.recv_service_response).to eq 'payload'
    end
  end

  describe 'the cumulative bound on a reassembled response' do
    # Each chunk is legal on its own and the chunk count is nowhere near spent,
    # so this is the case neither of the other two ceilings catches: without a
    # running total, 64 chunks of this size would reassemble to 140 MB.
    let(:payload) { 'x' * 2_200_000 }

    it 'fails on the running total before the chunk count runs out' do
      data = msg_chunk('C', payload) + msg_chunk('C', payload) + msg_chunk('F', 'tail')

      expect { stream_over(data).recv_service_response }
        .to raise_error(Rex::Proto::OpcUa::Error::FramingError, /reassembled response exceeded the 4194304 byte ceiling/)
    end

    it 'accepts each of those chunks on its own' do
      expect(stream_over(msg_chunk('F', payload)).recv_service_response.bytesize).to eq payload.bytesize
    end

    # The bound is on the total rather than on the chunk that crosses it, so the
    # second chunk is refused for what it would add, not for its own size.
    it 'counts what has already been reassembled' do
      data = msg_chunk('C', payload) + msg_chunk('F', 'x' * 2_000_000)

      expect { stream_over(data).recv_service_response }
        .to raise_error(Rex::Proto::OpcUa::Error::FramingError, /reassembled response exceeded/)
    end

    it 'allows a response that reaches the ceiling exactly' do
      exact = 'x' * (Rex::Proto::OpcUa::Tcp::MAX_MESSAGE_SIZE / 2)
      data = msg_chunk('C', exact) + msg_chunk('F', exact)

      expect(stream_over(data).recv_service_response.bytesize).to eq Rex::Proto::OpcUa::Tcp::MAX_MESSAGE_SIZE
    end

    # Once a size has been negotiated the two ceilings are consistent with each
    # other: 64 chunks of 65535 bytes cannot reach 4 MB, so the chunk count is
    # what a server runs into first and the running total is the backstop for a
    # connection that never negotiated one.
    it 'is not reachable within the chunk count once a size has been negotiated' do
      stream = stream_over('')
      stream.negotiate(hello, acknowledge(65_535))
      largest = stream.max_chunk_size - Rex::Proto::OpcUa::Tcp::HEADER_LEN -
                Rex::Proto::OpcUa::Tcp::SECURE_MSG_PREFIX_LEN

      expect(largest * Rex::Proto::OpcUa::Tcp::MAX_CHUNKS).to be < Rex::Proto::OpcUa::Tcp::MAX_MESSAGE_SIZE
    end
  end
end
