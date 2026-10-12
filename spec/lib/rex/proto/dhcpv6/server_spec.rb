# -*- coding: binary -*-

require 'spec_helper'

RSpec.describe Rex::Proto::DHCPv6::Server do
  let(:const) { Rex::Proto::DHCPv6::Constants }
  let(:packet) { Rex::Proto::DHCPv6::Packet }

  subject(:server) do
    described_class.new(
      dns_servers: ['fe80::53'],
      assigned_address: 'fe80::dead',
      server_mac: 'aa:bb:cc:dd:ee:ff'
    )
  end

  def solicit
    packet.new(
      msg_type: const::MessageType::SOLICIT,
      transaction_id: "\x01\x02\x03",
      options: [
        { code: const::OptionCode::CLIENTID, data: packet.duid_ll('11:22:33:44:55:66') },
        { code: const::OptionCode::IA_NA, data: [0xcafef00d, 0, 0].pack('NNN') }
      ]
    ).to_binary_s
  end

  describe '#handle_request' do
    it 'answers a Solicit with an Advertise handing out the attacker as DNS' do
      msg_type, response = server.handle_request(solicit)
      expect(msg_type).to eq(const::MessageType::SOLICIT)

      reply = packet.read(response)
      expect(reply.msg_type).to eq(const::MessageType::ADVERTISE)
      dns = reply.find_option(const::OptionCode::DNS_SERVERS)
      expect(Rex::Socket.addr_ntoa(dns.data.to_binary_s)).to eq('fe80::53')
    end

    it 'uses the configured server MAC in the server DUID' do
      _msg_type, response = server.handle_request(solicit)
      server_id = packet.read(response).find_option(const::OptionCode::SERVERID)
      expect(server_id.data.to_binary_s).to eq(packet.duid_ll('aa:bb:cc:dd:ee:ff'))
    end

    it 'returns nil for a message type it does not answer' do
      release = packet.new(msg_type: const::MessageType::RELEASE, transaction_id: 'abc').to_binary_s
      expect(server.handle_request(release)).to be_nil
    end

    it 'returns nil (and does not raise) on malformed input' do
      expect(server.handle_request("\xff")).to be_nil
    end
  end

  describe '#initialize' do
    it 'generates a random locally-administered server DUID when no MAC is given' do
      s = described_class.new(dns_servers: ['fe80::53'])
      # DUID-LL: type(2) + hwtype(2) + 6-byte MAC; first MAC byte 0x02 = locally administered
      expect(s.server_duid.bytesize).to eq(10)
      expect(s.server_duid[4].unpack1('C')).to eq(0x02)
    end
  end
end
