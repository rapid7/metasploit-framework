require 'spec_helper'
require 'rex/proto/tftp/server'

RSpec.describe Rex::Proto::TFTP::Server do
  subject(:server) { described_class.new }

  let(:socket) { instance_double(UDPSocket) }
  let(:destination) { ['192.0.2.1', 49152] }
  let(:packet) { "\x00\x03\x00\x01test\x00\xff".b }

  before do
    server.instance_variable_set(:@sock, socket)
  end

  describe '#send_packet' do
    it 'sends the binary packet with zero flags to the destination' do
      expect(socket).to receive(:send)
        .with(packet, 0, destination[0], destination[1])
        .and_return(packet.bytesize)

      expect(server.send_packet(destination, packet)).to eq(packet.bytesize)
    end

    it 'does not modify the packet' do
      original = packet.dup
      allow(socket).to receive(:send).and_return(packet.bytesize)

      server.send_packet(destination, packet)

      expect(packet).to eq(original)
    end

    it 'propagates socket errors to the caller' do
      expect(socket).to receive(:send)
        .with(packet, 0, destination[0], destination[1])
        .and_raise(Errno::ENETUNREACH)

      expect do
        server.send_packet(destination, packet)
      end.to raise_error(Errno::ENETUNREACH)
    end
  end
end
