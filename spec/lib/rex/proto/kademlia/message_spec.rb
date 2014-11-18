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

  describe '#decode_pong' do
    it 'does not decode overly small pongs' do
      expect(kad.decode_pong("\xE4\x61\x01")).to eq(nil)
    end

    it 'does not decode overly large pongs' do
      expect(kad.decode_pong("\xE4\x61\x01\x02\x03")).to eq(nil)
    end

    it 'properly decodes valid pongs' do
      expect(kad.decode_pong("\xE4\x61\x9E\x86")).to eq(34462)
    end
  end

  describe '#decode_bootstrap_peer' do
    it 'does not decode overly small peer responses' do
      expect(kad.decode_bootstrap_peer("this is too small")).to eq(nil)
    end

    it 'does not decode overly large peer responses' do
      expect(kad.decode_bootstrap_peer("this is much, much, much too large")).to eq(nil)
    end

    it 'properly extracts peer info' do
      data =
          "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F" + # peer ID
          "\x04\x28\xA8\xC0" + # 192.168.40.4
          "\x31\xd4" + # UDP port 54321
          "\x39\x30" + # TCP port 12345
          "\x08" # peer type
      peer_id, ip, udp_port, tcp_port, type = kad.decode_bootstrap_peer(data)
      expect(peer_id).to eq('3020100070605040B0A09080F0E0D0C')
      expect(ip).to eq('192.168.40.4')
      expect(udp_port).to eq(54321)
      expect(tcp_port).to eq(12345)
      expect(type).to eq(8)
    end
  end

  describe '#decode_bootstrap_peers' do
    it 'does not decode overly small bootstrap responses' do
      expect(kad.decode_bootstrap_peer("this is too small")).to eq(nil)
    end

    it 'does not decode overly large bootstrap responses' do
      expect(kad.decode_bootstrap_peer("this is large enough but truncated")).to eq(nil)
    end

    it 'properly extracts peers info' do
      data =
          "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F" + # peer ID
          "\x04\x28\xA8\xC0" + # 192.168.40.4
          "\x31\xd4" + # UDP port 54321
          "\x39\x30" + # TCP port 12345
          "\x08" + # peer type
          "\x01\x01\x02\x02\x03\x03\x04\x04\x05\x05\x06\x06\x07\x07\x08\x08" + # peer ID
          "\x05\x28\xA8\xC0" + # 192.168.40.5
          "\x5c\x11" + # UDP port 4444
          "\xb3\x15" + # TCP port 5555
          "\x09" # peer type
      peers = kad.decode_bootstrap_peers(data)
      expect(peers.size).to eq(2)
      peer1_id, peer1_ip, peer1_udp, peer1_tcp, peer1_type = peers.first
      expect(peer1_id).to eq('3020100070605040B0A09080F0E0D0C')
      expect(peer1_ip).to eq('192.168.40.4')
      expect(peer1_udp).to eq(54321)
      expect(peer1_tcp).to eq(12345)
      expect(peer1_type).to eq(8)
      peer2_id, peer2_ip, peer2_udp, peer2_tcp, peer2_type = peers.last
      expect(peer2_id).to eq('2020101040403030606050508080707')
      expect(peer2_ip).to eq('192.168.40.5')
      expect(peer2_udp).to eq(4444)
      expect(peer2_tcp).to eq(5555)
      expect(peer2_type).to eq(9)
    end
  end

  describe '#decode_bootstrap_res' do
    it 'properly decodes valid bootstrap responses' do
      data = IO.read(File.join(File.dirname(__FILE__), 'kademlia_bootstrap_res.bin'))
      peer_id, tcp, version, peers = kad.decode_bootstrap_res(data)
      expect(peer_id).to eq('B54A83462529B21EF51FD54B956B07B0')
      expect(tcp).to eq(4662)
      expect(version).to eq(8)
      # don't bother checking every peer
      expect(peers.size).to eq(20)
    end
  end

  describe '#decode_peer_id' do
    it 'decodes a peer ID properly' do
      bytes = "\x00\x60\x89\x9B\x0A\x0B\xBE\xAE\x45\x35\xCB\x0E\x07\xA1\x77\x71"
      peer_id = "9B896000AEBE0B0A0ECB35457177A107"
      expect(kad.decode_peer_id(bytes)).to eq(peer_id)
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
