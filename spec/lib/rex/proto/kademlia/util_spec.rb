# -*- coding: binary -*-
#
require 'spec_helper'
require 'rex/proto/kademlia/util'

RSpec.describe Rex::Proto::Kademlia do

  describe '#decode_peer_id' do
    subject(:kad) { described_class.decode_peer_id(bytes) }
    let(:bytes) { "\x00\x60\x89\x9B\x0A\x0B\xBE\xAE\x45\x35\xCB\x0E\x07\xA1\x77\x71" }
    it 'decodes a peer ID properly' do
      is_expected.to eq('9B896000AEBE0B0A0ECB35457177A107')
    end
  end

  describe '#encode_peer' do
    skip 'encodes a peer ID properly' do
      bytes = "\x00\x60\x89\x9B\x0A\x0B\xBE\xAE\x45\x35\xCB\x0E\x07\xA1\x77\x71"
      peer_id = "9B896000AEBE0B0A0ECB35457177A107"
      expect(kad.encode_peer_id(peer_id)).to eq(bytes)
    end
  end
end
