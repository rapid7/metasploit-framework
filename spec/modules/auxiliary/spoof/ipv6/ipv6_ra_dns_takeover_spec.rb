require 'spec_helper'

RSpec.describe 'auxiliary/spoof/ipv6/ipv6_ra_dns_takeover' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) do
    load_and_create_module(
      module_type: 'auxiliary',
      reference_name: 'spoof/ipv6/ipv6_ra_dns_takeover'
    )
  end

  let(:cli) { double('cli', peerhost: 'fe80::5', peerport: 546) }
  let(:dns_service) { double('service') }

  before do
    mod.datastore['TARGET_DOMAIN'] = 'kerberos.issue'
    mod.datastore['SPOOF_IP6'] = 'dead:beef::53'
    mod.service = dns_service
  end

  def query_bytes(name, type)
    Dnsruby::Message.new(name, type).encode
  end

  def captured_response
    captured = nil
    allow(dns_service).to receive(:send_response) { |_cli, data| captured = data }
    yield
    Rex::Proto::DNS::Packet.encode_drb(captured)
  end

  describe '#on_dispatch_request (via shared NamePoisoner)' do
    it 'poisons an in-scope AAAA query with the spoof address' do
      resp = captured_response { mod.on_dispatch_request(cli, query_bytes('dc1.kerberos.issue', 'AAAA')) }
      aaaa = resp.answer.find { |rr| rr.type == 'AAAA' }
      expect(aaaa).not_to be_nil
      expect(aaaa.address.to_s.downcase).to eq('dead:beef::53')
    end

    it 'forwards out-of-scope queries to the default handler' do
      expect(dns_service).to receive(:default_dispatch_request).with(cli, kind_of(String))
      expect(dns_service).not_to receive(:send_response)
      mod.on_dispatch_request(cli, query_bytes('www.example.com', 'AAAA'))
    end

    it 'logs the peer as an IPv6-safe bracketed authority, not a bare host:port' do
      allow(dns_service).to receive(:send_response)
      expect(mod).to receive(:print_good).with(a_string_matching(/\[fe80::5\]:546/))
      mod.on_dispatch_request(cli, query_bytes('dc1.kerberos.issue', 'AAAA'))
    end
  end

  describe '#run validation' do
    it 'rejects a non-IPv6 SPOOF_IP6' do
      mod.datastore['SPOOF_IP6'] = '10.0.0.1'
      expect { mod.run }.to raise_error(Msf::Auxiliary::Failed, /SPOOF_IP6 must be a valid IPv6/)
    end

    it 'rejects an RA_INTERVAL below 1, since 0 or negative would flood the segment' do
      mod.datastore['RA_INTERVAL'] = 0
      expect { mod.run }.to raise_error(Msf::Auxiliary::Failed, /RA_INTERVAL must be >= 1/)
    end
  end

  describe 'SRVHOST default (from shared NamePoisoner)' do
    it 'defaults to :: so the DNS server binds IPv6 and receives the steered queries' do
      expect(mod.datastore['SRVHOST']).to eq('::')
    end

    it 'forwards an in-scope A query instead of answering it with the IPv6 SRVHOST' do
      # With an IPv6 SRVHOST there is no meaningful A answer, so the query is
      # forwarded (victim stays functional) rather than poisoned with a bogus
      # address such as the old 0.0.0.0 default.
      expect(dns_service).to receive(:default_dispatch_request).with(cli, kind_of(String))
      expect(dns_service).not_to receive(:send_response)
      mod.on_dispatch_request(cli, query_bytes('dc1.kerberos.issue', 'A'))
    end
  end

  describe '#handle_router_solicitation' do
    before do
      mod.instance_variable_set(:@ra_smac, '00:11:22:33:44:55')
      mod.instance_variable_set(:@ra_shost, 'fe80::1')
      mod.instance_variable_set(:@ra_domains, [])
      mod.instance_variable_set(:@ra_router_lifetime, 0)
    end

    def router_solicitation(src_mac: 'aa:bb:cc:dd:ee:ff', src_addr: 'fe80::5')
      p = PacketFu::IPv6Packet.new
      p.eth_saddr = src_mac
      p.ipv6_saddr = src_addr
      p.ipv6_daddr = 'ff02::2'
      p.ipv6_next = 0x3a
      p.payload = [133, 0, 0, 0].pack('CCnN')
      p.to_s
    end

    it 'answers a solicitation with a unicast RA back to the solicitor' do
      injected = nil
      allow(mod).to receive(:inject) { |data| injected = data }

      expect(mod.send(:handle_router_solicitation, router_solicitation)).to be(true)

      ra = PacketFu::Packet.parse(injected)
      expect(ra.eth_daddr).to eq('aa:bb:cc:dd:ee:ff')
      expect(ra.ipv6_daddr).to eq('fe80::5')
      expect(ra.icmpv6_type).to eq(134) # Router Advertisement
    end

    it 'multicasts the RA when the solicitation source is unspecified' do
      injected = nil
      allow(mod).to receive(:inject) { |data| injected = data }

      mod.send(:handle_router_solicitation, router_solicitation(src_addr: '::'))

      ra = PacketFu::Packet.parse(injected)
      expect(ra.ipv6_daddr).to eq('ff02::1')
    end

    it 'ignores a nil read and does not inject' do
      expect(mod).not_to receive(:inject)
      expect(mod.send(:handle_router_solicitation, nil)).to be(false)
    end

    it 'ignores non-solicitation traffic' do
      allow(mod).to receive(:inject)
      p = PacketFu::IPv6Packet.new
      p.ipv6_next = 0x3a
      p.payload = [128, 0, 0, 0].pack('CCnN') # Echo request, not a solicitation
      expect(mod).not_to receive(:inject)
      expect(mod.send(:handle_router_solicitation, p.to_s)).to be(false)
    end
  end
end
