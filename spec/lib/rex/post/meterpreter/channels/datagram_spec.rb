# frozen_string_literal: true

require 'spec_helper'
require 'rex/socket/udp'
require 'rex/post/meterpreter/channels/datagram'

RSpec.describe Rex::Post::Meterpreter::Datagram do
  subject(:channel) { described_class.new(nil, nil, nil, 0, nil) }

  before do
    channel.lsock.extend(Rex::Socket::Udp)
    channel.lsock.initsock
    channel.lsock.extend(described_class::SocketInterface)
    channel.lsock.channel = channel
  end

  after do
    channel.lsock.close unless channel.lsock.closed?
    channel.rsock.close unless channel.rsock.closed?
  end

  describe 'SocketInterface#recvfrom_nonblock' do
    it 'reads the synthetic sockaddr independently from the requested payload length' do
      channel.rsock.syswrite('response')
      channel.rsock.syswrite(Rex::Socket.to_sockaddr('192.0.2.53', 53))

      data, host, port = channel.lsock.recvfrom(1, 2)

      expect(data).to eq('r')
      expect(host).to eq('192.0.2.53')
      expect(port).to eq(53)
    end
  end
end
