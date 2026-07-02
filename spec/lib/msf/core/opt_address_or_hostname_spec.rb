# -*- coding: binary -*-

require 'spec_helper'

RSpec.describe Msf::OptAddressOrHostname do
  iface = NetworkInterface.interfaces.collect do |iface|
    ip_address = NetworkInterface.addresses(iface).values.flatten.collect { |x| x['addr'] }.select do |addr|
      IPAddr.new(addr).ipv4? && !addr[/^127.*/]
    rescue IPAddr::InvalidAddressError
      false
    end.sort_by do |addr|
      ip_addr = IPAddr.new(addr)
      [ip_addr.ipv4? ? 0 : 1, ip_addr.to_i]
    end.first
    { name: iface, addr: ip_address }
  end.select { |name_addr| name_addr[:addr] }.sort_by do |name_addr|
    ip_addr = IPAddr.new(name_addr[:addr])
    [ip_addr.ipv4? ? 0 : 1, ip_addr.to_i]
  end.first

  valid_values = [
    { value: '192.0.2.1',    normalized: '192.0.2.1' },
    { value: '127.0.0.1',    normalized: '127.0.0.1' },
    { value: '2001:db8::',   normalized: '2001:db8::' },
    { value: '::1',          normalized: '::1' },
    # Tunnel / proxy hostnames that may not be locally resolvable
    { value: 'tunnel.example.com', normalized: 'tunnel.example.com' },
    { value: 'abc123.ngrok.io', normalized: 'abc123.ngrok.io' },
    { value: 'example.com',  normalized: 'example.com' },
  ] + (iface ? [{ value: iface[:name], normalized: iface[:addr] }] : [])

  invalid_values = [
    # Wildcard bind addresses are not valid callback addresses for LHOST
    { value: '0.0.0.0' },
    { value: '0::0' },
    # Malformed IPv6
    { value: '0:::0' },
    { value: '0:0:0' },
    # Garbage strings
    { value: 'not a hostname!' },
    { value: 'has space.com' },
    # Non-string values
    { value: true },
    { value: 5 },
    { value: [] },
    { value: [1, 2] },
    { value: {} },
  ]

  it_behaves_like 'an option', valid_values, invalid_values, 'address'

  let(:opt) { described_class.new('LHOST', [false, 'test']) }

  describe '#valid?' do
    context 'with tunnel hostnames' do
      it 'accepts without requiring DNS resolution' do
        allow(::Rex::Socket).to receive(:getaddress).and_raise(::SocketError)
        expect(opt.valid?('tunnel.example.com')).to be_truthy
      end
    end

    context 'with resolve_names: true' do
      let(:opt) { described_class.new('LHOST', [false, 'test'], resolve_names: true) }

      it 'accepts a hostname that resolves' do
        allow(::Rex::Socket).to receive(:getaddress).with('tunnel.example.com', true).and_return('1.2.3.4')
        expect(opt.valid?('tunnel.example.com')).to be_truthy
      end

      it 'rejects a hostname that does not resolve' do
        allow(::Rex::Socket).to receive(:getaddress).with('tunnel.example.com', true).and_raise(::SocketError)
        expect(opt.valid?('tunnel.example.com')).to be_falsey
      end
    end

    context 'with interface name errors' do
      before do
        allow(NetworkInterface).to receive(:interfaces).and_raise(NetworkInterface::Error)
      end

      it 'rescues and falls back to IP/hostname checks' do
        expect(opt).to receive(:elog).with(an_instance_of(NetworkInterface::Error)).at_least(:once)
        expect(opt.valid?('192.0.2.1')).to be_truthy
      end
    end
  end

  describe '#normalize' do
    context 'with a hostname' do
      it 'returns the hostname unchanged' do
        expect(opt.normalize('tunnel.example.com')).to eq 'tunnel.example.com'
      end
    end

    context 'with an IPv6 address in non-canonical form' do
      it 'normalizes via IPAddr' do
        expect(opt.normalize('0::0')).to eq '::'
      end
    end

    context 'with an interface name' do
      let(:mock_iface) { 'mock0' }
      let(:mock_addresses) do
        { 2 => [{ 'addr' => '192.0.2.1', 'netmask' => '255.255.255.0', 'broadcast' => '192.0.2.255' }] }
      end

      before do
        allow(NetworkInterface).to receive(:interfaces).and_return([mock_iface])
        allow(NetworkInterface).to receive(:addresses).with(mock_iface).and_return(mock_addresses)
      end

      it 'resolves to the interface IPv4 address' do
        expect(opt.normalize(mock_iface)).to eq '192.0.2.1'
      end
    end
  end
end
