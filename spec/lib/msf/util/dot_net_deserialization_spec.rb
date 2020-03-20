require 'rex'
require 'msf/util/dot_net_deserialization'

RSpec.describe Msf::Util::DotNetDeserialization do
  describe '#generate' do
    it 'generates formatted payloads' do
      gadget_chain = Msf::Util::DotNetDeserialization.generate_gadget_chain('command')
      payload = Msf::Util::DotNetDeserialization.generate('command', formatter: :LosFormatter)
      expect(gadget_chain).to_not eq payload
    end

    it 'generates unformatted payloads' do
      gadget_chain = Msf::Util::DotNetDeserialization.generate_gadget_chain('command')
      payload = Msf::Util::DotNetDeserialization.generate('command', formatter: nil)
      expect(gadget_chain).to eq payload
    end
  end

  describe '#generate_formatted' do
    it 'should raise a NotImplementedError for an unsupported formatter' do
      expect{
        Msf::Util::DotNetDeserialization.generate_formatted("\x00", formatter: :DoesNotExist)
      }.to raise_error(NotImplementedError)
    end

    context 'when formatting using the LosFormatter it' do
      formatted = Msf::Util::DotNetDeserialization.generate('command', formatter: :LosFormatter)
      it 'should start with ObjectStateFormatter' do
        osf = Msf::Util::DotNetDeserialization::ObjectStateFormatter.new
        osf.read(formatted)
        expect(osf.marker_format).to eq 0xff
        expect(osf.marker_version).to eq 1
        expect(osf.token).to eq 50  # Token_BinarySerialized
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
      )
      it 'should start with a SerializationHeaderRecord' do
        header = Msf::Util::DotNetDeserialization::SerializationHeaderRecord.new
        header.read(gadget_chain)
        expect(header.major_version).to eq 1
        expect(header.minor_version).to eq 0
        expect(header.root_id).to eq 1
      end

      it 'should end with MessageEnd' do
        message_end = Msf::Util::DotNetDeserialization::MessageEnd.new
        expect(gadget_chain.ends_with? message_end.to_binary_s).to be_truthy
      end
    end
  end

  describe 'LengthPrefixedString' do
    LengthPrefixedString = Msf::Util::DotNetDeserialization::LengthPrefixedString
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
