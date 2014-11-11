# -*- coding: binary -*-
require 'spec_helper'
require 'rex/proto/steam/message'

describe Rex::Proto::Steam do
  subject do
    mod = Module.new
    mod.extend described_class
    mod
  end

  describe '#encode_message' do
    it 'should properly encode messages' do
      message = subject.encode_message('T', 'Test')
      expect(message).to eq("\xFF\xFF\xFF\xFF\x54Test")
    end
  end

  describe '#decode_message' do
    it 'should not decode overly short messages' do
      expect(subject.decode_message('foo')).to eq(nil)
    end

    it 'should not decode unknown messages' do
      expect(subject.decode_message("\xFF\xFF\xFF\x01blahblahblah")).to eq(nil)
    end

    it 'should properly decode valid messages' do
      header, type, message = subject.decode_message("\xFF\xFF\xFF\xFF\x54Test")
      expect(header).to eq(Rex::Proto::Steam::UNFRAGMENTED_HEADER)
      expect(type).to eq(0x54)
      expect(message).to eq('Test')
    end
  end

  describe '#a2s_info_decode' do
    it 'should extract a2s_info fields properly' do
      example_resp = "\xff\xff\xff\xff\x49\x11\x2d\x3d\x54\x48\x45\x20\x42\x41\x54\x54\x4c\x45\x47\x52\x4f\x55\x4e\x44\x53\x20\x2a\x48\x41\x52\x44\x43\x4f\x52\x45\x2a\x3d\x2d\x00\x61\x6f\x63\x5f\x62\x61\x74\x74\x6c\x65\x67\x72\x6f\x75\x6e\x64\x00\x61\x67\x65\x6f\x66\x63\x68\x69\x76\x61\x6c\x72\x79\x00\x41\x67\x65\x20\x6f\x66\x20\x43\x68\x69\x76\x61\x6c\x72\x79\x00\x66\x44\x16\x20\x00\x64\x6c\x00\x01\x31\x2e\x30\x2e\x30\x2e\x36\x00\xb1\x87\x69\x04\x04\x7c\x35\xbe\x12\x40\x01\x48\x4c\x73\x74\x61\x74\x73\x58\x3a\x43\x45\x2c\x69\x6e\x63\x72\x65\x61\x73\x65\x64\x5f\x6d\x61\x78\x70\x6c\x61\x79\x65\x72\x73\x00\x66\x44\x00\x00\x00\x00\x00\x00"
      expected_info = {:version=>17, :name=>"-=THE BATTLEGROUNDS *HARDCORE*=-", :map=>"aoc_battleground", :folder=>"ageofchivalry", :game_name=>"Age of Chivalry", :game_id=>17510, :players=>"22/32", :bots=>0, :game_version=>"1.0.0.6", :type=>"Dedicated", :environment=>"Linux", :visibility=>"public", :VAC=>"secured"}
      actual_info = subject.a2s_info_decode(example_resp)
      expect(actual_info).to eq(expected_info)
    end
  end
end
