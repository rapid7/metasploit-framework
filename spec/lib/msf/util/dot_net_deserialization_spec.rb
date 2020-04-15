require 'rex'
require 'msf/util/dot_net_deserialization'

RSpec.describe Msf::Util::DotNetDeserialization do
  describe '#generate' do
    COMMAND = 'ping 127.0.0.1'

    it 'generates correct gadget chains' do
      # this is a quick but important check to ensure consistency of the
      # serialized payloads which are deterministic
      table = {
        :TextFormattingRunProperties => '8aa639e141b325e8bf138d09380bdf7714f70c72',
        :TypeConfuseDelegate         => '97cf63717ea751f81c382bd178fdf56d0ec3edb1',
        :WindowsIdentity             => '8dab1805a165cabea8ce96a7721317096f072166'
      }
      table.each do |gadget_chain, correct_digest|
        stream = Msf::Util::DotNetDeserialization.generate(COMMAND, gadget_chain: gadget_chain)
        expect(stream).to be_kind_of String
        real_digest = OpenSSL::Digest::SHA1.digest(stream).each_byte.map { |b| b.to_s(16).rjust(2, '0') }.join
        expect(real_digest).to eq correct_digest
      end
    end

    it 'generates parsable gadget chains' do
      Msf::Util::DotNetDeserialization::GadgetChains::NAMES.each do |gadget_chain|
        serialized = Msf::Util::DotNetDeserialization.generate(COMMAND, gadget_chain: gadget_chain)
        stream = Msf::Util::DotNetDeserialization::Types::SerializedStream.new
        stream.read(serialized)
        expect(stream.to_binary_s).to eq serialized
      end
    end
  end

  describe '#generate_formatted' do
    stream = Msf::Util::DotNetDeserialization.generate_gadget_chain(COMMAND, gadget_chain: :TextFormattingRunProperties)

    it 'should raise a NotImplementedError for an unsupported formatter' do
      expect{
        Msf::Util::DotNetDeserialization.generate_formatted(stream, formatter: :DoesNotExist)
      }.to raise_error(NotImplementedError)
    end

    context 'when formatting using the LosFormatter it' do
      formatted = Msf::Util::DotNetDeserialization.generate_formatted(stream, formatter: :LosFormatter)

      it 'should be a string' do
        expect(formatted).to be_kind_of String
      end

      it 'should start with ObjectStateFormatter' do
        osf = Msf::Util::DotNetDeserialization::Formatters::LosFormatter::ObjectStateFormatter.new
        osf.read(formatted)
        expect(osf.marker_format).to eq 0xff
        expect(osf.marker_version).to eq 1
        expect(osf.token).to eq 50  # Token_BinarySerialized
      end
    end

    context 'when formatting using the SoapFormatter it' do
      formatted = Msf::Util::DotNetDeserialization.generate_formatted(stream, formatter: :SoapFormatter)

      it 'should be a string' do
        expect(formatted).to be_kind_of String
      end

      it 'should be valid XML' do
        xml = Nokogiri::XML(formatted)
        expect(xml.errors.length).to eq 0
      end
    end
  end

  describe '#generate_gadget_chain' do
    it 'should raise a NotImplementedError for an unsupported gadget chain' do
      expect{
        Msf::Util::DotNetDeserialization.generate_gadget_chain('command', gadget_chain: :DoesNotExist)
      }.to raise_error(NotImplementedError)
    end

    context 'when generating a TextFormattingRunProperties it' do
      gadget_chain =  Msf::Util::DotNetDeserialization.generate_gadget_chain(
        'command',
        gadget_chain: :TextFormattingRunProperties
      ).to_binary_s
      it 'should start with a SerializationHeaderRecord' do
        record = Msf::Util::DotNetDeserialization::Types::Record.new
        record.read(gadget_chain)

        expect(record.record_type).to eq Msf::Util::DotNetDeserialization::Types::RecordValues::SerializationHeaderRecord::RECORD_TYPE

        header = record.record_value
        expect(header.major_version).to eq 1
        expect(header.minor_version).to eq 0
        expect(header.root_id).to eq 1
      end

      it 'should end with MessageEnd' do
        message_end = Msf::Util::DotNetDeserialization::Types::Record.from_value(
          Msf::Util::DotNetDeserialization::Types::RecordValues::MessageEnd.new
        )
        expect(gadget_chain.ends_with? message_end.to_binary_s).to be_truthy
      end
    end
  end

  describe 'LengthPrefixedString' do
    LengthPrefixedString = Msf::Util::DotNetDeserialization::Types::Primitives::LengthPrefixedString
    it 'parses well-formed strings' do
      lps = LengthPrefixedString.new
      expect(lps.read("\x01A")).to eq "A"
      expect(lps.read([0x80, 0x01].pack('C*') + ('A' * 0x80))).to eq ('A' * 0x80)
    end

    it 'generates well-formed strings' do
      expect(LengthPrefixedString.new('A').to_binary_s).to eq "\x01A"
      expect(LengthPrefixedString.new('A' * 0x80).to_binary_s).to eq [0x80, 0x01].pack('C*') + ('A' * 0x80)
    end
  end
end
