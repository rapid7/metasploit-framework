require 'postgres/postgres-pr/message'

RSpec.describe Msf::Db::PostgresPR::Message do
  let(:mock_socket_clazz) do
    Class.new do
      include Rex::IO::Stream

      def initialize(data)
        @read_data = data || ''
      end

      def read(n, _opts = {})
        result, remaining = @read_data[0...n], @read_data[n..-1]
        @read_data = remaining
        result
      end
    end
  end

  def mock_socket(data)
    mock_socket_clazz.new(data)
  end

  describe '.read' do
    let(:startup) { false }
    let(:stream_bytes) { '' }
    let(:result) { described_class.read(mock_socket(stream_bytes), startup) }

    context 'when reading a SASL authentication message' do
      # Offered SASL mechanisms
      let(:stream_bytes) { "R\x00\x00\x00\x17\x00\x00\x00\nSCRAM-SHA-256\x00\x00".b }

      it 'parses a SCRAM-SHA-256 message' do
        expect(result).to be_a(Msf::Db::PostgresPR::AuthenticationSASL)
        expect(result.mechanisms).to eq(['SCRAM-SHA-256'])
        expect(result.dump).to eq(stream_bytes)
      end
    end

    context 'when reading a SASL continue message' do
      # First SCRAM-SHA-256 server message
      # https://datatracker.ietf.org/doc/html/rfc7677#section-3
      let(:stream_bytes) do
        "R\x00\x00\x00\\\x00\x00\x00\vr=2kRpTcHEFyoG+UgDEpRBdVcJLTWh5WtxARhYOHcG27i7YxAi,s=GNpgixWS5E4INbrMf665Kw==,i=4096".b
      end

      it 'parses a generic SASL message' do
        expect(result).to be_a(Msf::Db::PostgresPR::AuthenticationSASLContinue)
        expect(result.value).to eq('r=2kRpTcHEFyoG+UgDEpRBdVcJLTWh5WtxARhYOHcG27i7YxAi,s=GNpgixWS5E4INbrMf665Kw==,i=4096')
        expect(result.dump).to eq(stream_bytes)
      end
    end

    context 'when reading a SASL final message' do
      # Final SCRAM-SHA-256 server message
      # https://datatracker.ietf.org/doc/html/rfc7677#section-3
      let(:stream_bytes) do
        "R\x00\x00\x006\x00\x00\x00\fv=b10lbmDELI8EHr/DM47cmcVcwn2n4TgQC4d1gaE6QHI=".b
      end

      it 'parses a generic SASL message' do
        expect(result).to be_a(Msf::Db::PostgresPR::AuthenticationSASLFinal)
        expect(result.value).to eq('v=b10lbmDELI8EHr/DM47cmcVcwn2n4TgQC4d1gaE6QHI=')
        expect(result.dump).to eq(stream_bytes)
      end
    end
  end

  describe Msf::Db::PostgresPR::SASLResponseMessage do
    # Final SCRAM-SHA-256 client message
    # https://datatracker.ietf.org/doc/html/rfc7677#section-3
    let(:stream_bytes) do
      "p\x00\x00\x00lc=biws,r=8P6L/8Vv+sEUZitMm7hnoNppbiGwnpKXKGXU1HqFPGjD6gtm,p=lpmyxOY7t6U+um1eCG/LLGS0fiFsieTgDv0EwJ8etso=".b
    end

    describe '#parse' do
      it 'parses the value' do
        subject.parse(Msf::Db::Buffer.new(stream_bytes))
        expect(subject).to be_a(described_class)
        expect(subject.value).to eq('c=biws,r=8P6L/8Vv+sEUZitMm7hnoNppbiGwnpKXKGXU1HqFPGjD6gtm,p=lpmyxOY7t6U+um1eCG/LLGS0fiFsieTgDv0EwJ8etso=')
      end
    end

    describe '#dump' do
      it 'dumps the value' do
        subject.parse(Msf::Db::Buffer.new(stream_bytes))
        expect(subject.dump).to eq(stream_bytes)
      end
    end
  end
end
