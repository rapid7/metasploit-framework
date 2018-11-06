require 'spec_helper'

RSpec.describe RubySMB::SMB2::CreateContext do
  subject(:struct) { described_class.new }

  it { is_expected.to respond_to :next_offset }
  it { is_expected.to respond_to :name_offset }
  it { is_expected.to respond_to :name_length }
  it { is_expected.to respond_to :data_offset }
  it { is_expected.to respond_to :data_length }
  it { is_expected.to respond_to :name }
  it { is_expected.to respond_to :data }

  describe '#name_length' do
    it 'stores the length of the name field' do
      expect(struct.name_length).to eq struct.name.length
    end
  end

  describe '#name_offset' do
    it 'stores the relative offset of the name field' do
      expect(struct.name_offset).to eq struct.name.rel_offset
    end
  end

  describe '#data_length' do
    it 'stores the length of the data field' do
      expect(struct.data_length).to eq struct.data.length
    end
  end

  describe '#data_offset' do
    it 'stores the relative offset of the data field' do
      struct.data = 'Hello'
      expect(struct.data_offset).to eq struct.data.rel_offset
    end

    it 'returns 0 if the data field is empty' do
      expect(struct.data_offset).to eq 0
    end
  end
end
