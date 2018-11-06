require 'spec_helper'

RSpec.describe RubySMB::Fscc::FileFullEaInfo do
  subject(:info) { described_class.new }

  it { is_expected.to respond_to :next_entry_offset }
  it { is_expected.to respond_to :flags }
  it { is_expected.to respond_to :ea_name_length }
  it { is_expected.to respond_to :ea_value_length }
  it { is_expected.to respond_to :ea_name }
  it { is_expected.to respond_to :ea_value }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#flags' do
    it 'is an extended_attribute_flag' do
      expect(info.flags).to be_a RubySMB::Field::ExtendedAttributeFlag
    end
  end

  describe '#ea_name_length' do
    it 'stores the length of the #ea_name field' do
      expect(info.ea_name_length).to eq info.ea_name.do_num_bytes
    end
  end

  describe '#ea_value_length' do
    it 'stores the length of the #ea_value field' do
      expect(info.ea_value_length).to eq info.ea_value.do_num_bytes
    end
  end
end
