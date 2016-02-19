# -*- coding: binary -*-
require 'spec_helper'

require 'rex/proto/natpmp/packet'
RSpec.describe Rex::Proto::NATPMP do
  subject do
    mod = Module.new
    mod.extend described_class
    mod
  end

  describe '#parse_external_address_response' do
    it 'should properly parse non-error responses' do
      data = "\x00\x80\x00\x00\x00\x33\x50\x53\xc0\xa8\x01\x02"
      subject.parse_external_address_response(data)
      ver, opcode, result, epoch, addr = subject.parse_external_address_response(data)
      expect(ver).to eq(0)
      expect(opcode).to eq(128)
      expect(result).to eq(0)
      expect(epoch).to eq(3362899)
      expect(addr).to eq('192.168.1.2')
    end
    it 'should properly parse error responses' do
      data = "\x00\x80\x00\x03\x00\x00\x70\x90\x00\x00\x00\x00"
      subject.parse_external_address_response(data)
      ver, opcode, result, epoch, addr = subject.parse_external_address_response(data)
      expect(ver).to eq(0)
      expect(opcode).to eq(128)
      expect(result).to eq(3)
      expect(epoch).to eq(28816)
      expect(addr).to eq('0.0.0.0')
    end
  end

  describe '#parse_map_port_response' do
    it 'should properly parse responses' do
      data = "\x00\x82\x00\x00\x00\x33\x6f\xd8\x11\x5c\x15\xb3\x00\x36\xee\x80"
      ver, opcode, result, epoch, internal, external, lifetime = subject.parse_map_port_response(data)
      expect(ver).to eq(0)
      expect(opcode).to eq(130)
      expect(result).to eq(0)
      expect(epoch).to eq(3370968)
      expect(internal).to eq(4444)
      expect(external).to eq(5555)
      expect(lifetime).to eq(3600000)
    end
  end
end
