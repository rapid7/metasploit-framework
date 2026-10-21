# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Rex::Proto::TFTP::Server do
  subject(:server) { described_class.allocate }

  let(:sock) { instance_double(Rex::Socket::Udp) }
  let(:peer) { ['192.0.2.10', 1234] }
  let(:packet) { "\x00\x03\x00\x01test\x00\xff".b }

  describe '#send_packet' do
    before { server.sock = sock }

    it 'sends the packet with flags 0 to the peer host and port' do
      expect(sock).to receive(:send).with('pkt', 0, '192.0.2.10', 1234)
      server.__send__(:send_packet, peer, 'pkt')
    end

    it 'does not use the deprecated sendto' do
      allow(sock).to receive(:send)
      expect(sock).not_to receive(:sendto)
      server.__send__(:send_packet, peer, 'pkt')
    end

    it 'does not modify binary packet data' do
      original = packet.dup
      allow(sock).to receive(:send).and_return(packet.bytesize)

      server.__send__(:send_packet, peer, packet)

      expect(packet).to eq(original)
    end

    it 'propagates socket errors to the caller' do
      expect(sock).to receive(:send)
        .with(packet, 0, peer[0], peer[1])
        .and_raise(Errno::ENETUNREACH)

      expect do
        server.__send__(:send_packet, peer, packet)
      end.to raise_error(Errno::ENETUNREACH)
    end
  end
end
