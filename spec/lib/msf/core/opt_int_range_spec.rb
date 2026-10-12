# -*- coding:binary -*-

require 'spec_helper'

RSpec.describe Msf::OptIntRange do
  valid_values = [
    { :value => '1',         :normalized => '1'   },
    { :value => '1,2',       :normalized => '1,2' },
    { :value => '1, 2, 3-5', :normalized => '1,2,3-5' },
  ]
  invalid_values = [
    { :value => "bbq" },
    { :value => "0.1" },
    { :value => "0xG" },
    { :value => "FF"  },
  ]

  it_behaves_like "an option", valid_values, invalid_values, 'integer range'

  describe '.parse' do
    it 'parses a single number to a single number' do
      expect(described_class.parse('1')).to be_a Enumerator
      expect(described_class.parse('1').to_a).to eq [1]
    end

    it 'parses a range of numbers to multiple numbers' do
      expect(described_class.parse('1-3')).to be_a Enumerator
      expect(described_class.parse('1-3').to_a).to eq [1, 2, 3]
    end

    it 'parses a mixture to multiple numbers' do
      expect(described_class.parse('1-3,5')).to be_a Enumerator
      expect(described_class.parse('1-3,5').to_a).to eq [1, 2, 3, 5]
    end

    it 'parses a range with a single number exclusion' do
      expect(described_class.parse('1-3,!2')).to be_a Enumerator
      expect(described_class.parse('1-3,!2').to_a).to eq [1, 3]
    end

    it 'parses a range with a range number exclusion' do
      expect(described_class.parse('1-5,!2-3')).to be_a Enumerator
      expect(described_class.parse('1-5,!2-3').to_a).to eq [1, 4, 5]
    end
  end

  describe '#valid? with a maximum' do
    subject { described_class.new('RIDS', [true, 'The RIDs to enumerate'], maximum: 100) }

    it 'rejects a single value above the maximum' do
      expect(subject.valid?('150')).to be false
    end

    it 'rejects a range that extends above the maximum' do
      expect(subject.valid?('1-200')).to be false
    end

    it 'accepts a value at the maximum' do
      expect(subject.valid?('100')).to be true
    end

    it 'accepts ranges within the maximum' do
      expect(subject.valid?('1-50,60-100')).to be true
    end

    it 'ignores excluded numbers above the maximum' do
      expect(subject.valid?('1-50,!200')).to be true
    end
  end

  describe '#valid? without a maximum' do
    subject { described_class.new('RIDS', [true, 'The RIDs to enumerate']) }

    it 'does not constrain how large a value may be' do
      expect(subject.valid?('1-1000000')).to be true
    end
  end
end


