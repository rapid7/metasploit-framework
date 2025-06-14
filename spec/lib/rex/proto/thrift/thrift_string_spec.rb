# -*- coding: binary -*-
require 'spec_helper'
require 'rex/text'

RSpec.describe Rex::Proto::Thrift::ThriftString do
  let(:value) { Rex::Text.rand_text_alphanumeric(10) }
  let(:binary_s) { [value.length].pack('N') + value }

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
