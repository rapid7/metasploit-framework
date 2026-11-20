# -*- coding:binary -*-

require 'spec_helper'

RSpec.describe Msf::OptInt do
  valid_values = [
    { :value => "1",    :normalized => 1  },
    { :value => "10",   :normalized => 10 },
    { :value => "0",    :normalized => 0  },
    { :value => "0x10", :normalized => 16 },
    { :value => "0x0a", :normalized => 10 },
    { :value => "0x0A", :normalized => 10 },
    { :value => "0xFf", :normalized => 255},
    { :value => "-1",   :normalized => -1 },
  ]
  invalid_values = [
    { :value => "yer mom", },
    { :value => "0.1",     },
    { :value => "0xG",     },
    { :value => "FF",      },
  ]

  it_behaves_like "an option", valid_values, invalid_values, 'integer'

  describe "with a minimum and maximum" do
    subject { described_class.new('COUNT', [false, 'Loop count'], minimum: 1, maximum: 50) }

    it "accepts a value on the lower bound" do
      expect(subject.valid?('1')).to be_truthy
    end

    it "accepts a value on the upper bound" do
      expect(subject.valid?('50')).to be_truthy
    end

    it "rejects a value below the minimum" do
      expect(subject.valid?('0')).to be_falsey
    end

    it "rejects a value above the maximum" do
      expect(subject.valid?('51')).to be_falsey
    end

    it "rejects a negative value" do
      expect(subject.valid?('-1')).to be_falsey
    end

    it "honours the range for hexadecimal input" do
      expect(subject.valid?('0x0a')).to be_truthy # 10, in range
      expect(subject.valid?('0x40')).to be_falsey # 64, out of range
    end

    it "exposes the bounds" do
      expect(subject.minimum).to eq 1
      expect(subject.maximum).to eq 50
    end

    it "appends the range to the description" do
      expect(subject.desc).to eq 'Loop count (range: 1-50)'
    end
  end

  describe "with a single allowed value" do
    subject { described_class.new('Q', [false, 'single'], minimum: 7, maximum: 7) }

    it "accepts exactly that value" do
      expect(subject.valid?('7')).to be_truthy
      expect(subject.valid?('6')).to be_falsey
      expect(subject.valid?('8')).to be_falsey
    end

    it "appends the range to the description" do
      expect(subject.desc).to eq 'single (range: 7-7)'
    end
  end

  describe "with zero bounds" do
    it "accepts zero as a minimum" do
      expect(described_class.new('N', [false, 'lo'], minimum: 0).valid?('0')).to be_truthy
      expect(described_class.new('N', [false, 'lo'], minimum: 0).valid?('-1')).to be_falsey
    end

    it "accepts zero as a maximum" do
      expect(described_class.new('N', [false, 'hi'], maximum: 0).valid?('0')).to be_truthy
      expect(described_class.new('N', [false, 'hi'], maximum: 0).valid?('1')).to be_falsey
      expect(described_class.new('N', [false, 'hi'], maximum: 0).valid?('-5')).to be_truthy
    end
  end

  describe "with only a minimum" do
    subject { described_class.new('N', [false, 'lower only'], minimum: 10) }

    it "rejects a value below the minimum" do
      expect(subject.valid?('9')).to be_falsey
    end

    it "accepts a value at or above the minimum" do
      expect(subject.valid?('10')).to be_truthy
      expect(subject.valid?('9999')).to be_truthy
    end

    it "notes the minimum in the description" do
      expect(subject.desc).to eq 'lower only (minimum: 10)'
    end
  end

  describe "with only a maximum" do
    subject { described_class.new('N', [false, 'upper only'], maximum: 100) }

    it "rejects a value above the maximum" do
      expect(subject.valid?('101')).to be_falsey
    end

    it "accepts a value at or below the maximum, including negatives" do
      expect(subject.valid?('100')).to be_truthy
      expect(subject.valid?('-5')).to be_truthy
    end

    it "notes the maximum in the description" do
      expect(subject.desc).to eq 'upper only (maximum: 100)'
    end
  end

  it "raises when the minimum is greater than the maximum" do
    expect { described_class.new('N', [false, 'bad'], minimum: 50, maximum: 1) }.to raise_error(ArgumentError)
  end

  describe "with a default" do
    it "uses the default verbatim even when it falls outside the bounds, but rejects it on validation" do
      opt = described_class.new('N', [true, 'has default', '5'], minimum: 10)
      expect(opt.default).to eq '5'
      expect(opt.valid?('5')).to be_falsey
    end
  end

  it "behaves as an unbounded integer option when no range is given" do
    opt = described_class.new('N', [false, 'no range'])
    expect(opt.valid?('-2147483648')).to be_truthy
    expect(opt.valid?('2147483647')).to be_truthy
    expect(opt.desc).to eq 'no range'
    expect(opt.minimum).to be_nil
    expect(opt.maximum).to be_nil
  end
end
