# -*- coding:binary -*-
require 'spec_helper'

require 'net/dns'

RSpec.describe Net::DNS::RR::Classes do

  subject do
    described_class.new
  end

  describe '#initialize' do
    subject(:rr_class) do
      described_class.allocate
    end

    it 'raises when initialized with no args' do
      expect { rr_class.send(:initialize) }.to raise_error(ArgumentError)
    end

    it 'respects default RR class when initialized with a nil RR class' do
      rr_class.send(:initialize, nil)
      expect(rr_class.to_i).to eql(1)
      expect(rr_class.to_s).to eql('IN')
    end

    # TODO: figure out why this doesn't work
    skip 'respects configured default RR class' do
      rr_class.send(:default=, 'NONE')
      expect(rr_class.to_i).to eql(254)
      expect(rr_class.to_s).to eql('NONE')
    end

    it 'initializes with a valid RR class Integer argument' do
      rr_class.send(:initialize, 4)
      expect(rr_class.to_i).to eql(4)
      expect(rr_class.to_s).to eql('HS')
    end

    it 'raises when the supplied RR class Integer is invalid' do
      expect { rr_class.send(:initialize, 123456) }.to raise_error(ClassArgumentError)
      expect { rr_class.send(:initialize, -1) }.to raise_error(ClassArgumentError)
    end

    it 'initializes with a valid RR class String argument' do
      rr_class.send(:initialize, 'CH')
      expect(rr_class.to_i).to eql(3)
      expect(rr_class.to_s).to eql('CH')
      rr_class.send(:initialize, 'CLASS9')
      expect(rr_class.to_i).to eql(9)
      expect(rr_class.to_s).to eql('CLASS9')
      rr_class.send(:initialize, 'CLASS1')
      expect(rr_class.to_i).to eql(1)
      expect(rr_class.to_s).to eql('IN')
    end

    it 'raises when the supplied RR class String is invalid' do
      expect { rr_class.send(:initialize, 'cats') }.to raise_error(ClassArgumentError)
      expect { rr_class.send(:initialize, 'CLASS123456') }.to raise_error(ClassArgumentError)
    end
  end
end
