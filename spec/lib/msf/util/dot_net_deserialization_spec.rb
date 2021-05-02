require 'rex'

RSpec.shared_examples 'a valid serialized stream' do |stream|
  it 'should start with a SerializedStreamHeader record' do
    expect(stream.records[0].record_type).to eq Msf::Util::DotNetDeserialization::Enums::RecordTypeEnum[:SerializedStreamHeader]
  end

  it 'should end with a MessageEnd record' do
    expect(stream.records[-1].record_type).to eq Msf::Util::DotNetDeserialization::Enums::RecordTypeEnum[:MessageEnd]
  end
end

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

    Msf::Util::DotNetDeserialization::GadgetChains::NAMES.each do |gadget_chain|
      describe "parsed gadget chain #{gadget_chain}" do
        serialized = Msf::Util::DotNetDeserialization.generate(COMMAND, gadget_chain: gadget_chain)
        stream = Msf::Util::DotNetDeserialization::Types::SerializedStream.read(serialized)

        it_behaves_like 'a valid serialized stream', stream

        it 'should be the same when serialized' do
          expect(stream.to_binary_s).to eq serialized
        end
      end
    end
  end

  describe '#generate_formatted' do
    stream = Msf::Util::DotNetDeserialization.generate_gadget_chain(COMMAND, gadget_chain: :TextFormattingRunProperties)

    it 'should raise a NotImplementedError for an unsupported formatter' do
      expect {
        Msf::Util::DotNetDeserialization.generate_formatted(stream, formatter: :DoesNotExist)
      }.to raise_error(NotImplementedError)
    end

    context 'when formatting using the BinaryFormatter it' do
      formatted = Msf::Util::DotNetDeserialization.generate_formatted(stream, formatter: :BinaryFormatter)

      it 'should be a string' do
        expect(formatted).to be_kind_of String
      end

      it_behaves_like 'a valid serialized stream', Msf::Util::DotNetDeserialization::Types::SerializedStream.read(formatted)
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
        expect(xml.errors.select { |error| error.fatal? }.length).to eq 0
      end
    end
  end

  describe '#generate_gadget_chain' do
    it 'should raise a NotImplementedError for an unsupported gadget chain' do
      expect {
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

  describe 'Assemblies' do
    Assemblies = Msf::Util::DotNetDeserialization::Assemblies
    mscorlib = Assemblies::VERSIONS['4.0.0.0']['mscorlib']
    describe 'StrongName' do
      it 'should convert to a string correctly' do
        expect("#{mscorlib}").to be_kind_of String
        expect(mscorlib.to_s =~ /mscorlib, Version=\S+, Culture=\S+, PublicKeyToken=[a-f0-9]{16}/).to be_truthy
      end

      it 'should provide QualifiedName objects from key lookups' do
        expect(mscorlib['System.String']).to be_kind_of Msf::Util::DotNetDeserialization::Assemblies::QualifiedName
      end
    end
  end

  describe 'Types::Primitives::EnumArray' do
    EnumArray = Msf::Util::DotNetDeserialization::Types::Primitives::EnumArray
    it 'accepts an array of symbols' do
      ea = EnumArray.new(%i{ Boolean Byte Char }, enum: Msf::Util::DotNetDeserialization::Enums::PrimitiveTypeEnum)
      expect(ea.length).to eq 3
      expect(ea.to_binary_s).to eq "\x01\x02\x03"
    end

    it 'accepts an array of integers' do
      ea = EnumArray.new([1, 2, 3], enum: Msf::Util::DotNetDeserialization::Enums::PrimitiveTypeEnum)
      expect(ea.length).to eq 3
      expect(ea.to_binary_s).to eq "\x01\x02\x03"
    end
  end

  describe 'Types::Primitives::LengthPrefixedString' do
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

  describe 'Types::RecordValues::ClassWithMembersAndTypes' do
    ClassWithMembersAndTypes = Msf::Util::DotNetDeserialization::Types::RecordValues::SystemClassWithMembersAndTypes

    it 'raises an ArgumentError when there is a member count mismatch' do
      expect {
        ClassWithMembersAndTypes.from_member_values(
          class_info: Msf::Util::DotNetDeserialization::Types::General::ClassInfo.new,
          member_type_info: Msf::Util::DotNetDeserialization::Types::General::MemberTypeInfo.new,
          member_values: [ 1 ]
        )
      }.to raise_error(ArgumentError)
    end
  end

  describe 'Types::RecordValues::SystemClassWithMembersAndTypes' do
    SystemClassWithMembersAndTypes = Msf::Util::DotNetDeserialization::Types::RecordValues::SystemClassWithMembersAndTypes

    it 'raises an ArgumentError when there is a member count mismatch' do
      expect {
        SystemClassWithMembersAndTypes.from_member_values(
          class_info: Msf::Util::DotNetDeserialization::Types::General::ClassInfo.new,
          member_type_info: Msf::Util::DotNetDeserialization::Types::General::MemberTypeInfo.new,
          member_values: [ 1 ]
        )
      }.to raise_error(ArgumentError)
    end
  end

  describe 'Types::SerializedStream' do
    SerializedStream = Msf::Util::DotNetDeserialization::Types::SerializedStream

    it 'stops parsing a stream on EoF' do
      stream = SerializedStream.new.read("")
      expect(stream.records.length).to eq 0
    end

    it 'stops parsing a stream at a MessageEnd record' do
      stream  = SerializedStream.new.read("\x0b\xff")
      expect(stream.records.length).to eq 1
    end

    it 'should raise a IndexError for an unsupported record type' do
      expect{
        SerializedStream.new.read("\xff")
      }.to raise_error(IndexError)
    end

    describe '#get_object' do
      it 'should fetch values with a primitive id argument' do
        id = BinData::Int8.new(rand(0xff))
        value = rand(0x1000)
        stream = SerializedStream.new
        stream.set_object(id, value)
        expect(id).to be_kind_of BinData::BasePrimitive
        expect(stream.get_object(id)).to eq value
        expect(stream.get_object(id.value)).to eq value
      end
    end
  end
end
