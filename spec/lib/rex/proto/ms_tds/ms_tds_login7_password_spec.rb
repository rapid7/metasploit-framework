RSpec.describe Rex::Proto::MsTds::MsTdsLogin7Password do
  describe '#read' do
    let(:instance) { described_class.new(read_length: 20) }

    it 'reads an encoded password' do
      instance.read("\xa0\xa5\xb3\xa5\x92\xa5\x92\xa5\xd2\xa5\x53\xa5\x82\xa5\xe3\xa5\xb6\xa5\xb7\xa5".b)
      expect(instance.value).to eq 'Password1!'.encode(Encoding::UTF_16LE)
    end

    it 'reads an decoded password' do
      instance.read("P\x00a\x00s\x00s\x00w\x00o\x00r\x00d\x001\x00!\x00".b)
      expect(instance.value).to eq 'Password1!'.encode(Encoding::UTF_16LE)
    end
  end

  describe '#to_binary_s' do
    context 'when encode is true' do
      let(:instance) { described_class.new('Password1!', encode: true) }

      it 'does encode the password' do
        expect(instance.to_binary_s).to eq "\xa0\xa5\xb3\xa5\x92\xa5\x92\xa5\xd2\xa5\x53\xa5\x82\xa5\xe3\xa5\xb6\xa5\xb7\xa5".b
      end
    end

   context 'when encode is false' do
      let(:instance) { described_class.new('Password1!', encode: false) }

      it 'does not encode the password' do
        expect(instance.to_binary_s).to eq "P\x00a\x00s\x00s\x00w\x00o\x00r\x00d\x001\x00!\x00".b
      end
    end
  end

  describe '.decode' do
    let(:decoded) { described_class.decode("\xa0\xa5\xb3\xa5\x92\xa5\x92\xa5\xd2\xa5\x53\xa5\x82\xa5\xe3\xa5\xb6\xa5\xb7\xa5".b) }
    it 'decodes an encoded password' do
      expect(decoded).to eq 'Password1!'.encode(Encoding::UTF_16LE)
    end

    it 'returns the value in UTF_16LE encoding' do
      expect(decoded.encoding).to eq Encoding::UTF_16LE
    end
  end

  describe '.encode' do
    let(:encoded) { described_class.encode('Password1!') }
    it 'encodes a plaintext password' do
      expect(encoded).to eq "\xa0\xa5\xb3\xa5\x92\xa5\x92\xa5\xd2\xa5\x53\xa5\x82\xa5\xe3\xa5\xb6\xa5\xb7\xa5".b
    end

    it 'returns the value in ASCII-8BIT encoding' do
      expect(encoded.encoding).to eq Encoding::ASCII_8BIT
    end
  end
end