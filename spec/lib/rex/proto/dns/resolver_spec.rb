# frozen_string_literal: true

require 'spec_helper'
require 'rex/proto/dns/resolver'
require 'rex/socket/udp'

RSpec.describe Rex::Proto::DNS::Resolver do
  subject(:resolver) { described_class.new(config_file: nil, nameservers: [], log_file: File::NULL) }

  let(:udp_answer) { ['answer', ['AF_INET', 53, '192.0.2.53', '192.0.2.53']] }

  let(:socket) do
    double(
      'Rex::Socket::Udp',
      close: nil,
      closed?: false,
      timed_recvfrom: udp_answer,
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

      expect(answer).to eq(udp_answer)
    end

    it 'closes the UDP socket after a timeout' do
      allow(socket).to receive(:timed_recvfrom).and_raise(Timeout::Error)
      expect(socket).to receive(:close)

      expect(resolver.send_udp(nil, 'query', [['192.0.2.53', {}]])).to be_nil
    end
  end
end
