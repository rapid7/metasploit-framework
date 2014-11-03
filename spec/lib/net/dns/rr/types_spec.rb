# -*- coding:binary -*-
require 'spec_helper'

require 'net/dns'

describe Net::DNS::RR::Types do

  subject do
    described_class.new
  end

  describe '#initialize' do
    subject(:type) do
      described_class.allocate
    end

    it 'raises when initialized with no args' do
      expect { type.send(:initialize) }.to raise_error(ArgumentError)
    end

    it 'respects default type when initialized with a nil type' do
      type.send(:initialize, nil)
      expect(type.to_i).to eql(1)
      expect(type.to_s).to eql('A')
    end

    # TODO: figure out why this doesn't work
    skip 'respects configured default type' do
      type.send(:default=, 'CNAME')
      expect(type.to_i).to eql(5)
      expect(type.to_s).to eql('CNAME')
    end

    it 'initializes with a valid Fixnum argument' do
      type.send(:initialize, 1)
      expect(type.to_i).to eql(1)
      expect(type.to_s).to eql('A')
    end

    it 'raises when the supplied Fixnum is invalid' do
      expect { type.send(:initialize, 123456) }.to raise_error(TypeArgumentError)
      expect { type.send(:initialize, -1) }.to raise_error(TypeArgumentError)
    end

    it 'initializes with a valid String argument' do
      type.send(:initialize, 'SRV')
      expect(type.to_i).to eql(33)
      expect(type.to_s).to eql('SRV')
    end

    it 'raises when the supplied String is invalid' do
      expect { type.send(:initialize, 'cats') }.to raise_error(TypeArgumentError)
    end
  end
end
