require 'msf/core'

RSpec.describe Net::DNS::Names do
  subject do
    obj = Object.new
    obj.extend(described_class)
  end

  describe '#dn_expand' do
    context 'when offset is great than packet length' do
      let(:packet) do
        'AAAAA'
      end

      let(:offset) do
        10
      end

      it 'raises an ExpandError exception' do
        expect { subject.dn_expand(packet, offset) }.to raise_exception(ExpandError)
      end
    end

    context 'when packet length is less than offset + INT16SZ' do
      let(:packet) do
        "\xc0"
      end

      let(:offset) do
        0
      end

      it 'raises an ExpandError exception' do
        expect { subject.dn_expand(packet, offset) }.to raise_exception(ExpandError)
      end
    end

    context 'when packet length is less than offset + packet length' do
      let(:packet) do
        'AAAAA'
      end

      let(:offset) do
        4
      end

      it 'raises an ExpandError exception' do
        expect { subject.dn_expand(packet, offset) }.to raise_exception(ExpandError)
      end
    end
  end

  describe '#pack_name' do
    context 'when name data size is larger than 255 bytes' do
      let(:name) do
        'A' * (255+1)
      end

      it 'raises an ArgumentError exception' do
        expect { subject.pack_name(name) }.to raise_exception(ArgumentError)
      end
    end

    context 'when label data is larger than 63 bytes' do
      let(:name) do
        'A' * (63+1) + '.'
      end

      it 'raises an ArgumentError exception' do
        expect { subject.pack_name(name) }.to raise_exception(ArgumentError)
      end 
    end
  end

  describe '#names_array' do
    let(:name) do
      "AAA.AAA"
    end

    it 'returns an Array' do
      expect(subject.names_array(name)).to be_kind_of(Array)
    end
  end

  describe '#dn_comp' do
    let(:name) do
      'AAAA'
    end

    let(:offset) do
      0
    end

    let(:compnames) do
      {}
    end

    it 'returns 3 values' do
      v = subject.dn_comp(name, offset, compnames)
      expect(v.length).to eq(3)
      expect(v[0]).to be_kind_of(String)
      expect(v[1]).to be_kind_of(Integer)
      expect(v[2]).to be_kind_of(Hash)
    end
  end

  describe '#valid?' do
    context 'when FQDN is valid' do
      let(:fqdn) do
        'example.com'
      end

      it 'returns the FQDN' do
        expect(subject.valid?(fqdn)).to eq(fqdn)
      end

    end

    context 'when FQDN is not valid' do
      let(:fqdn) do
        'INVALID'
      end

      it 'raises ArgumentError exception' do
        expect { subject.valid?(fqdn) }.to raise_exception(ArgumentError)
      end
    end
  end
end