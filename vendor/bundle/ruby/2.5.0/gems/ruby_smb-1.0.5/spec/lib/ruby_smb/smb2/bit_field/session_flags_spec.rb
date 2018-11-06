require 'spec_helper'

RSpec.describe RubySMB::SMB2::BitField::SessionFlags do
  subject(:flags) { described_class.new }

  it { is_expected.to respond_to :guest }
  it { is_expected.to respond_to :null }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#guest' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.guest).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :guest, 'v', 0x00000001
  end

  describe '#null' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.null).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :null, 'v', 0x00000002
  end
end
