# -*- coding: binary -*-
require 'spec_helper'
require 'rex/text'

RSpec.describe Rex::Proto::Thrift::ThriftBoolean do
  let(:value) { true }
  let(:binary_s) { "\x01".b }

  describe '#to_binary_s' do
    it 'should correctly encode' do
      expect(described_class.new(value).to_binary_s).to eq binary_s
    end
  end

  describe '.read' do
    it 'should correctly decode' do
      expect(described_class.read(binary_s)).to eq value
    end
  end
end
