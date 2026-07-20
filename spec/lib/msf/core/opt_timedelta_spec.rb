# -*- coding:binary -*-

require 'spec_helper'

RSpec.describe Msf::OptTimedelta do
  valid_values = [
    { value: '120', normalized: 120.0 },
    { value: '-5m', normalized: -300.0 },
    { value: '1h30m', normalized: 5_400.0 },
    { value: '2d', normalized: 172_800.0 },
    { value: '+1.5h', normalized: 5_400.0 }
  ]

  invalid_values = [
    { value: 'yolo' },
    { value: '1w' },
    { value: '5mfoo' }
  ]

  it_behaves_like 'an option', valid_values, invalid_values, 'timedelta'

  describe '#valid?' do
    it 'can enforce positive-only values' do
      subject = described_class.new('Duration', [true, 'Duration'], allow_negative: false)

      expect(subject.valid?('5m')).to be(true)
      expect(subject.valid?('-5m')).to be(false)
    end
  end
end