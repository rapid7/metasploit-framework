# -*- coding: binary -*-
require 'spec_helper'
require 'rex/text'

RSpec.describe Rex::Proto::Thrift::ThriftStruct do
  let(:text) { Rex::Text.rand_text_alphanumeric(10) }
  let(:value) { [
    { field_id: 1, data_type: Rex::Proto::Thrift::ThriftDataType::T_UTF7, data_value: text },
    { data_type: Rex::Proto::Thrift::ThriftDataType::T_STOP }
  ] }
  let(:binary_s) { [Rex::Proto::Thrift::ThriftDataType::T_UTF7, 1, text.length].pack('CnN') + text + "\x00".b }

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
