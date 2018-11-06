require 'spec_helper'

RSpec.describe RubySMB::Fscc::EaInfoArray do
  subject(:info_array) { described_class.new(type: :file_full_ea_info) }
  let(:first_ea) {
    ea = RubySMB::Fscc::FileFullEaInfo.new
    ea.ea_name  = 'First'
    ea.ea_value = 'First Value'
    ea
  }
  let(:second_ea) {
    ea = RubySMB::Fscc::FileFullEaInfo.new
    ea.ea_name  = 'Second'
    ea.ea_value = 'Second Value'
    ea
  }
  let(:additional_ea) {
    ea = RubySMB::Fscc::FileFullEaInfo.new
    ea.ea_name  = 'Additional'
    ea.ea_value = 'Additional Value'
    ea
  }

  it 'updates the offset of the first element when a second is appended' do
    info_array << first_ea
    info_array << second_ea
    expect(info_array[0].next_entry_offset).to eq info_array[1].rel_offset
  end

  it 'sets the last offset to 0' do
    info_array << first_ea
    expect(info_array[0].next_entry_offset).to eq 0
  end

  it 'updates offset when setting a particular element' do
    info_array << first_ea
    info_array << second_ea
    info_array[0] = additional_ea
    expect(info_array[0].next_entry_offset).to eq info_array[1].rel_offset
  end

  it 'raises an error when inserting an invalid object' do
    expect { info_array << 'Foo' }.to raise_error(ArgumentError)
  end

  it 'raises an error when setting an invalid value' do
    expect { info_array[0] = 'Foo' }.to raise_error(ArgumentError)
  end
end
