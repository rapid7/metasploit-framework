# -*- coding: binary -*-

require 'spec_helper'
require 'rex/proto/kademlia/bootstrap_response'

RSpec.describe Rex::Proto::Kademlia::BootstrapResponse do
  describe '#from_data' do
    it 'properly decodes real valid bootstrap responses' do
      data = IO.read(File.join(File.dirname(__FILE__), 'kademlia_bootstrap_res.bin'))
      response = described_class.from_data(data)
      expect(response.peer_id).to eq('B54A83462529B21EF51FD54B956B07B0')
      expect(response.tcp_port).to eq(4662)
      expect(response.version).to eq(8)
      # don't bother checking every peer
      expect(response.peers.size).to eq(20)
      peer = response.peers.first
      expect(peer[:id]).to eq('B0A5518388D66BC211B0B9F75B3DCB10')
      expect(peer[:ip]).to eq('149.91.116.59')
      expect(peer[:tcp_port]).to eq(4882)
      expect(peer[:udp_port]).to eq(4992)
      expect(peer[:version]).to eq(8)
      peer = response.peers.last
      expect(peer[:id]).to eq('9B896000AEBE0B0A0ECB35457177A107')
      expect(peer[:ip]).to eq('83.46.192.208')
      expect(peer[:tcp_port]).to eq(3662)
      expect(peer[:udp_port]).to eq(3672)
      expect(peer[:version]).to eq(8)
    end

    it 'does not decode overly small bootstrap responses' do
      expect(described_class.from_data('this is too small')).to eq(nil)
    end

    it 'does not decode malformed bootstrap responses' do
      expect(described_class.from_data('this is large enough but truncated')).to eq(nil)
    end
  end
end
