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
  end

  describe '#run validation' do
    it 'rejects a non-IPv6 SPOOF_IP6' do
      mod.datastore['SPOOF_IP6'] = '10.0.0.1'
      expect { mod.run }.to raise_error(Msf::Auxiliary::Failed, /SPOOF_IP6 must be a valid IPv6/)
    end
  end
end
