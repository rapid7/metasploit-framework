require 'rspec'

RSpec.describe 'IBM i TN5250 Signon Fingerprint' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject do
    load_and_create_module(
      module_type: 'auxiliary',
      reference_name: 'scanner/ibmi/tn5250_fingerprint'
    )
  end

  IAC = 0xff
  WILL = 0xfb
  DO = 0xfd
  SB = 0xfa
  SE = 0xf0
  EOR_CMD = 0xef
  OPT_BINARY = 0x00
  OPT_TERMTYPE = 0x18
  OPT_EOR = 0x19
  OPT_NEWENV = 0x27

  # A fake socket that hands back pre-canned chunks from #get_once (simulating
  # however TCP chose to segment the server's writes) and records our #put.
  class FakeSock
    attr_reader :written

    def initialize(chunks)
      @chunks = chunks.dup
      @written = ''.b
    end

    def get_once(_len = -1, _timeout = nil)
      @chunks.shift
    end

    def put(data)
      @written << data
      data.bytesize
    end
  end

  # Encode application bytes the way a TN5250E server does in BINARY mode:
  # double every 0xFF, then terminate the record with IAC EOR.
  def telnet_encode_record(bytes)
    bytes.bytes.flat_map { |b| b == IAC ? [IAC, IAC] : [b] }.pack('C*') + [IAC, EOR_CMD].pack('C*')
  end

  # A minimal but structurally valid Write-To-Display record: 2-byte length,
  # GDS type 0x12a0, two header bytes, then ESC(0x04) WTD(0x11) WCC, then a
  # payload that deliberately contains a raw 0xFF to exercise IAC unescaping.
  let(:wtd_payload) { [0xff, 0x41, 0x42].pack('C*') }
  let(:wtd_record) do
    [0x00, 0x20, 0x12, 0xa0, 0x00, 0x00, 0x04, 0x11, 0x00].pack('C*') + wtd_payload
  end

  let(:opening) { [IAC, DO, OPT_NEWENV, IAC, DO, OPT_TERMTYPE].pack('C*') }
  let(:send_newenv) do
    [IAC, SB, OPT_NEWENV].pack('C*') + 'SEND USERVAR "IBMRSEED" "CODEPAGE" "KBDTYPE"'.b + [IAC, SE].pack('C*')
  end
  let(:do_eor_binary) { [IAC, DO, OPT_EOR, IAC, DO, OPT_BINARY].pack('C*') }

  describe '#parse_telnet_stream' do
    it 'unescapes IAC IAC and stops at IAC EOR, dropping trailing bytes' do
      stream = [0x01, IAC, IAC, 0x02].pack('C*') + [IAC, EOR_CMD].pack('C*') + 'TRAILING'.b
      result = subject.parse_telnet_stream(stream)

      expect(result[:eor]).to be true
      expect(result[:data]).to eq([0x01, 0xff, 0x02].pack('C*'))
    end

    it 'collects DO/WILL options and subnegotiation payloads' do
      stream = opening + send_newenv + do_eor_binary
      result = subject.parse_telnet_stream(stream)

      expect(result[:options]).to include([DO, OPT_NEWENV], [DO, OPT_TERMTYPE], [DO, OPT_EOR], [DO, OPT_BINARY])
      expect(result[:subneg].first.getbyte(0)).to eq(OPT_NEWENV)
      expect(result[:eor]).to be false
    end

    it 'leaves a trailing incomplete command unconsumed' do
      stream = [0x41, IAC, DO].pack('C*') # IAC DO <option not yet arrived>
      result = subject.parse_telnet_stream(stream)

      expect(result[:consumed]).to eq(1) # only the 0x41 data byte
      expect(result[:data]).to eq([0x41].pack('C*'))
    end

    it 'leaves an unterminated subnegotiation unconsumed' do
      stream = [IAC, SB, OPT_NEWENV].pack('C*') + 'SEND'.b # no IAC SE yet
      result = subject.parse_telnet_stream(stream)

      expect(result[:subneg]).to be_empty
      expect(result[:consumed]).to eq(0)
    end
  end

  describe '#read_wtd_record' do
    it 'recovers a record split across several get_once chunks' do
      encoded = telnet_encode_record(wtd_record)
      mid = encoded.bytesize / 2
      sock = FakeSock.new([encoded.byteslice(0, mid), encoded.byteslice(mid..-1)])

      expect(subject.read_wtd_record(sock, 10)).to eq(wtd_record)
    end

    it 'skips leftover telnet commands carried in the seed (the coalesced case)' do
      encoded = telnet_encode_record(wtd_record)
      # Finding #1: the DO EOR / DO BINARY offer arrives glued to the start of
      # the record in one segment; that segment becomes read_wtd_record's seed.
      seed = do_eor_binary + encoded.byteslice(0, 4)
      rest = encoded.byteslice(4..-1)
      sock = FakeSock.new([rest])

      expect(subject.read_wtd_record(sock, 10, seed)).to eq(wtd_record)
    end

    it 'raises when the peer closes before the EOR terminator' do
      sock = FakeSock.new([[0x12, 0xa0].pack('C*'), nil])

      expect { subject.read_wtd_record(sock, 10) }.to raise_error(/connection closed/)
    end
  end

  describe '#perform_tn5250_negotiation' do
    it 'detects TN5250E and hands back a record coalesced with the final offer' do
      encoded = telnet_encode_record(wtd_record)
      # Phase 3 segment carries DO EOR/BINARY *and* the whole record together.
      sock = FakeSock.new([opening, send_newenv, do_eor_binary + encoded])

      info, seed = subject.perform_tn5250_negotiation(sock, 'IBM-3179-2', 10)

      expect(info[:enhanced]).to be true
      expect(info[:signon_bypass_offered]).to be true
      expect(info[:codepage_offered]).to be true
      # The coalesced record survived in the returned seed.
      expect(subject.read_wtd_record(sock, 10, seed)).to eq(wtd_record)
      # We answered WILL NEW-ENVIRON during negotiation.
      expect(sock.written).to include([IAC, WILL, OPT_NEWENV].pack('C*'))
    end

    it 'tolerates the opening DOs being split across two segments' do
      sock = FakeSock.new(
        [
          opening.byteslice(0, 3), # just DO NEW-ENVIRON
          opening.byteslice(3..-1), # then DO TERMINAL-TYPE
          send_newenv,
          do_eor_binary
        ]
      )

      info, = subject.perform_tn5250_negotiation(sock, 'IBM-3179-2', 10)
      expect(info[:enhanced]).to be true
    end

    it 'raises a clear error when the host does not open as a 5250 service' do
      sock = FakeSock.new(["HTTP/1.1 400 Bad Request\r\n".b, nil])

      expect { subject.perform_tn5250_negotiation(sock, 'IBM-3179-2', 10) }
        .to raise_error(/not a 5250 host/)
    end
  end

  describe '#extract_wtd_payload' do
    it 'returns the WTD order stream from a decoded record' do
      expect(subject.extract_wtd_payload(wtd_record)).to eq(wtd_payload)
    end

    it 'returns nil for a record without the GDS signon type' do
      expect(subject.extract_wtd_payload([0x00, 0x06, 0x00, 0x00, 0x00, 0x00].pack('C*'))).to be_nil
    end
  end
end
