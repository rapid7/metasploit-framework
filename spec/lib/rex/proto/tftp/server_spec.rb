# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Rex::Proto::TFTP::Server do
  subject(:server) { described_class.allocate }

  let(:sock) { instance_double(Rex::Socket::Udp) }
  let(:peer) { ['192.0.2.10', 1234] }

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
  end
end
