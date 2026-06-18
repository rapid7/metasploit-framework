# frozen_string_literal: true

require 'spec_helper'
require 'rex/proto/dns/resolver'
require 'rex/socket/udp'

RSpec.describe Rex::Proto::DNS::Resolver do
  subject(:resolver) { described_class.new(config_file: nil, nameservers: [], log_file: File::NULL) }

  let(:socket) do
    double(
      'Rex::Socket::Udp',
      close: nil,
      closed?: false,
      recvfrom: ['answer', '192.0.2.53', 53],
      write: nil
    )
  end

  describe '#send_udp' do
    before do
      allow(Rex::Socket::Udp).to receive(:create).and_return(socket)
    end

    it 'closes the UDP socket after receiving an answer' do
      expect(socket).to receive(:close)

      answer = resolver.send_udp(nil, 'query', [['192.0.2.53', {}]])

      expect(answer).to eq(['answer', '192.0.2.53', 53])
    end

    it 'closes the UDP socket after a timeout' do
      allow(socket).to receive(:recvfrom).and_raise(Timeout::Error)
      expect(socket).to receive(:close)

      expect(resolver.send_udp(nil, 'query', [['192.0.2.53', {}]])).to be_nil
    end
  end
end
