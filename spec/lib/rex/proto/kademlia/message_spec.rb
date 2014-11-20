# -*- coding: binary -*-
require 'spec_helper'
require 'rex/proto/kademlia/message'

describe Rex::Proto::Kademlia do
  subject(:kad) do
    mod = Module.new
    mod.extend described_class
    mod
  end

  describe '#encode_message' do
    let(:no_body) { "\xE4\x01" }
    let(:body) { "\xE4\x01p2p" }
    it 'properly encodes messages without a body' do
      expect(kad.encode_message(1)).to eq("\xE4\x01")
    end
    it 'properly encodes messages with a body' do
      expect(kad.encode_message(1, 'p2p')).to eq("\xE4\x01p2p")
    end
  end

  describe '#decode_message' do
    it 'does not decode overly short messages' do
      expect(kad.decode_message('f')).to eq(nil)
    end

    it 'does not decode unknown messages' do
      expect(kad.decode_message("this is not kademlia")).to eq(nil)
    end

    it 'raises on compressed messages' do
      expect do
        kad.decode_message("\xE5\x01blahblah")
      end.to raise_error(NotImplementedError)
    end

    it 'properly decodes valid messages without a body' do
      type, payload = kad.decode_message("\xE4\xFF")
      expect(type).to eq(0xFF)
      expect(payload).to eq('')
    end

    it 'properly decodes valid messages wth a body' do
      type, payload = kad.decode_message("\xE4\xFFtesttesttest")
      expect(type).to eq(0xFF)
      expect(payload).to eq('testtesttest')
    end
  end
end
