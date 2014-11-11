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
      expected_info = {
        version: 17, name: "-=THE BATTLEGROUNDS *HARDCORE*=-", map: "aoc_battleground",
        folder: "ageofchivalry", game_name: "Age of Chivalry", game_id: 17510,
        players: "22/32", bots: 0, game_version: "1.0.0.6", type: "Dedicated",
        environment: "Linux", visibility: "public", VAC: "secured"
      }
      actual_info = subject.a2s_info_decode(IO.read(File.join(File.dirname(__FILE__), 'steam_info.bin')))
      expect(actual_info).to eq(expected_info)
    end
  end
end
