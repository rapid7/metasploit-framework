# -*- coding:binary -*-
require 'spec_helper'

require 'net/dns'

RSpec.describe Net::DNS::RR::Types do

  subject do
    described_class.new
  end

  describe '#initialize' do
    subject(:rr_type) do
      described_class.allocate
    end

    it 'raises when initialized with no args' do
      expect { rr_type.send(:initialize) }.to raise_error(ArgumentError)
    end

    it 'respects default RR type when initialized with a nil RR type' do
      rr_type.send(:initialize, nil)
      expect(rr_type.to_i).to eql(1)
      expect(rr_type.to_s).to eql('A')
    end

    # TODO: figure out why this doesn't work
    skip 'respects configured default RR type' do
      rr_type.send(:default=, 'CNAME')
      expect(rr_type.to_i).to eql(5)
      expect(rr_type.to_s).to eql('CNAME')
    end

    it 'initializes with a valid RR type Integer argument' do
      rr_type.send(:initialize, 2)
      expect(rr_type.to_i).to eql(2)
      expect(rr_type.to_s).to eql('NS')
    end

    it 'raises when the supplied RR type Integer is invalid' do
      expect { rr_type.send(:initialize, 123456) }.to raise_error(TypeArgumentError)
      expect { rr_type.send(:initialize, -1) }.to raise_error(TypeArgumentError)
    end

    it 'initializes with a valid RR type String argument' do
      rr_type.send(:initialize, 'SRV')
      expect(rr_type.to_i).to eql(33)
      expect(rr_type.to_s).to eql('SRV')
      rr_type.send(:initialize, 'TYPE12')
      expect(rr_type.to_i).to eql(12)
      expect(rr_type.to_s).to eql('PTR')
      rr_type.send(:initialize, 'TYPE123')
      expect(rr_type.to_i).to eql(123)
      expect(rr_type.to_s).to eql('TYPE123')
    end

    it 'raises when the supplied RR type String is invalid' do
      expect { rr_type.send(:initialize, 'cats') }.to raise_error(TypeArgumentError)
      expect { rr_type.send(:initialize, 'TYPE123456') }.to raise_error(TypeArgumentError)
    end
  end
end
