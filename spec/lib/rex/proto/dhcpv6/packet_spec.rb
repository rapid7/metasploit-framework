# -*- coding: binary -*-

require 'spec_helper'

RSpec.describe Rex::Proto::DHCPv6::Packet do
  let(:const) { Rex::Proto::DHCPv6::Constants }
  let(:client_duid) { described_class.duid_ll('11:22:33:44:55:66') }
  let(:server_duid) { described_class.duid_ll('aa:bb:cc:dd:ee:ff') }

  def build_solicit(extra_options = [])
    described_class.new(
      msg_type: const::MessageType::SOLICIT,
      transaction_id: "\x01\x02\x03",
      options: [
        { code: const::OptionCode::CLIENTID, data: client_duid },
        { code: const::OptionCode::IA_NA, data: [0xdeadbeef, 0, 0].pack('NNN') }
      ] + extra_options
    )
  end

  describe 'wire encoding' do
    it 'round-trips a message through the wire format unchanged' do
      wire = build_solicit.to_binary_s
      expect(described_class.read(wire).to_binary_s).to eq(wire)
    end

    it 'lays out the header as type + 3-byte transaction id + TLV options' do
      wire = build_solicit.to_binary_s
      expect(wire[0].unpack1('C')).to eq(const::MessageType::SOLICIT)
      expect(wire[1, 3]).to eq("\x01\x02\x03".b)
      # first option: CLIENTID (code 1), length, then the DUID
      expect(wire[4, 2].unpack1('n')).to eq(const::OptionCode::CLIENTID)
      expect(wire[6, 2].unpack1('n')).to eq(client_duid.bytesize)
    end
  end

  describe '.duid_ll' do
    it 'encodes DUID type 3, ethernet hardware type, and the MAC bytes' do
      expect(client_duid).to eq("\x00\x03\x00\x01\x11\x22\x33\x44\x55\x66".b)
    end

    it 'accepts a MAC with dashes or raw bytes' do
      expect(described_class.duid_ll('11-22-33-44-55-66')).to eq(client_duid)
      expect(described_class.duid_ll("\x11\x22\x33\x44\x55\x66".b)).to eq(client_duid)
    end
  end

  describe '.dns_servers_option' do
    it 'packs each IPv6 address as 16 network-order bytes' do
      opt = described_class.dns_servers_option(['fe80::1', '2001:db8::2'])
      expect(opt.code).to eq(const::OptionCode::DNS_SERVERS)
      expect(opt.data.to_binary_s).to eq(Rex::Socket.addr_aton('fe80::1') + Rex::Socket.addr_aton('2001:db8::2'))
    end
  end

  describe '.request_iaid' do
    it 'reads the IAID out of the request IA_NA option' do
      expect(described_class.request_iaid(build_solicit)).to eq(0xdeadbeef)
    end

    it 'returns nil when there is no IA_NA' do
      info_req = described_class.new(msg_type: const::MessageType::INFORMATION_REQUEST, transaction_id: 'abc')
      expect(described_class.request_iaid(info_req)).to be_nil
    end
  end

  describe '.response_type_for' do
    it 'answers a Solicit with an Advertise' do
      expect(described_class.response_type_for(build_solicit)).to eq(const::MessageType::ADVERTISE)
    end

    it 'answers a Rapid-Commit Solicit with a Reply' do
      solicit = build_solicit([{ code: const::OptionCode::RAPID_COMMIT, data: '' }])
      expect(described_class.response_type_for(solicit)).to eq(const::MessageType::REPLY)
    end

    it 'answers a Request with a Reply' do
      req = described_class.new(msg_type: const::MessageType::REQUEST, transaction_id: 'abc')
      expect(described_class.response_type_for(req)).to eq(const::MessageType::REPLY)
    end

    it 'does not answer message types it does not handle (e.g. Release)' do
      rel = described_class.new(msg_type: const::MessageType::RELEASE, transaction_id: 'abc')
      expect(described_class.response_type_for(rel)).to be_nil
    end
  end

  describe '.build_response' do
    subject(:response) do
      described_class.build_response(
        request: described_class.read(build_solicit.to_binary_s),
        server_duid: server_duid,
        dns_servers: ['fe80::53'],
        assigned_address: 'fe80::dead',
        domain_list: ['kerberos.issue']
      )
    end

    it 'produces a wire-valid Advertise that echoes the transaction id' do
      expect(response.msg_type).to eq(const::MessageType::ADVERTISE)
      expect(response.transaction_id.to_binary_s).to eq("\x01\x02\x03".b)
      expect(described_class.read(response.to_binary_s).to_binary_s).to eq(response.to_binary_s)
    end

    it 'includes the server DUID and echoes the client DUID' do
      server_id = response.find_option(const::OptionCode::SERVERID)
      client_id = response.find_option(const::OptionCode::CLIENTID)
      expect(server_id.data.to_binary_s).to eq(server_duid)
      expect(client_id.data.to_binary_s).to eq(client_duid)
    end

    it 'hands out the attacker as DNS server' do
      dns = response.find_option(const::OptionCode::DNS_SERVERS)
      expect(Rex::Socket.addr_ntoa(dns.data.to_binary_s)).to eq('fe80::53')
    end

    it 'leases the assigned address in an IA_NA echoing the client IAID' do
      ia_na = response.find_option(const::OptionCode::IA_NA)
      expect(ia_na.data.to_binary_s[0, 4].unpack1('N')).to eq(0xdeadbeef)
      # IA_NA data = IAID(4) + T1(4) + T2(4), then a nested IAADDR option
      # (code(2) + len(2) + address(16) + lifetimes(8)); address starts at 12 + 4.
      iaaddr_option = ia_na.data.to_binary_s[12..]
      expect(iaaddr_option[0, 2].unpack1('n')).to eq(const::OptionCode::IAADDR)
      expect(Rex::Socket.addr_ntoa(iaaddr_option[4, 16])).to eq('fe80::dead')
    end

    it 'returns nil for a request type it does not answer' do
      release = described_class.new(msg_type: const::MessageType::RELEASE, transaction_id: 'abc')
      expect(described_class.build_response(request: release, server_duid: server_duid, dns_servers: ['fe80::53'])).to be_nil
    end

    it 'echoes Rapid Commit and replies when the client requested it' do
      solicit = described_class.read(build_solicit([{ code: const::OptionCode::RAPID_COMMIT, data: '' }]).to_binary_s)
      reply = described_class.build_response(request: solicit, server_duid: server_duid, dns_servers: ['fe80::53'])
      expect(reply.msg_type).to eq(const::MessageType::REPLY)
      expect(reply.find_option(const::OptionCode::RAPID_COMMIT)).not_to be_nil
    end
  end
end
