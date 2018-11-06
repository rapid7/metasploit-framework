RSpec.describe RubySMB::Nbss::NetbiosName do
  subject(:netbios_name) { described_class.new }

  it { is_expected.to respond_to :flag1 }
  it { is_expected.to respond_to :flag2 }
  it { is_expected.to respond_to :label_length }
  it { is_expected.to respond_to :label }
  it { is_expected.to respond_to :null_label }

  it 'is big endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :big
  end

  describe '#flag1' do
    it 'is a 1-bit field' do
      expect(netbios_name.flag1).to be_a BinData::Bit1
    end

    it 'is set to 0 by default' do
      expect(netbios_name.flag1).to eq 0
    end
  end

  describe '#flag2' do
    it 'is a 1-bit field' do
      expect(netbios_name.flag2).to be_a BinData::Bit1
    end

    it 'is set to 0 by default' do
      expect(netbios_name.flag2).to eq 0
    end
  end

  describe '#label_length' do
    it 'is a 6-bit field' do
      expect(netbios_name.label_length).to be_a BinData::Bit6
    end
  end

  describe '#label' do
    it 'is a string' do
      expect(netbios_name.label).to be_a BinData::String
    end

    it 'reads #label_length bytes' do
      str = 'ABCDEFGHIJ'
      netbios_name.label_length = 4
      expect(netbios_name.label.read(str)).to eq(str[0,4])
    end
  end

  describe '#null_label' do
    it 'is a string' do
      expect(netbios_name.null_label).to be_a BinData::String
    end

    it 'is always a NULL byte' do
      str = 'ABCD'
      expect(netbios_name.null_label.read(str)).to eq("\x00")
    end
  end

  describe '#nb_name_encode' do
    it 'encodes as expected' do
      input = 'TESTNB          '
      output = 'FEEFFDFEEOECCACACACACACACACACACA'
      expect(netbios_name.nb_name_encode(input)).to eq output
    end
  end

  describe '#nb_name_encode' do
    it 'decodes as expected' do
      input = 'FEEFFDFEEOECCACACACACACACACACACA'
      output = 'TESTNB          '
      expect(netbios_name.nb_name_decode(input)).to eq output
    end
  end

  describe '#get' do
    it 'returns the expected label' do
      label = 'TESTNB          '
      expect(netbios_name.assign(label)).to eq(label)
    end
  end

  describe '#set' do
    it 'sets the expected label and the label_length fields' do
      label = 'TESTNB          '
      netbios_name.assign(label)
      expect(netbios_name.label).to eq(netbios_name.nb_name_encode(label))
      expect(netbios_name.label_length).to eq(netbios_name.nb_name_encode(label).length)
    end
  end
end

