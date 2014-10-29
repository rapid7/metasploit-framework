# -*- coding: binary -*-
require 'spec_helper'

require 'msf/core/auxiliary/skinny'

describe Msf::Auxiliary::Skinny do
  subject do
    mod = Module.new
    mod.extend described_class
    mod
  end

  describe '#format_mac' do
    it 'should format MACs with allowed format' do
      expect(subject.format_mac('a:B:c0:1:2:30')).to eql('0A:0B:C0:01:02:30')
      expect(subject.format_mac('a-B-c0-1-2-30')).to eql('0A:0B:C0:01:02:30')
      expect(subject.format_mac('a-B:c0-1:2-30')).to eql('0A:0B:C0:01:02:30')
      expect(subject.format_mac('a1b2c3d4e5f6')).to eql('A1:B2:C3:D4:E5:F6')
    end

    it 'should not format MACs with bad format' do
      expect{subject.format_mac('a:c0:1:2:30')}.to raise_error(ArgumentError)
      expect{subject.format_mac('a:a:a:c0:1:2:30')}.to raise_error(ArgumentError)
      expect{subject.format_mac('a:b:c:d:e:z')}.to raise_error(ArgumentError)
      expect{subject.format_mac('12345678901')}.to raise_error(ArgumentError)
    end
  end
end
