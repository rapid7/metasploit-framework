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
    { value: '0.0.0.0',      normalized: '0.0.0.0' },
    { value: '2001:db8::',   normalized: '2001:db8::' },
    { value: '::1',          normalized: '::1' },
    { value: '0::0',         normalized: '::' },
    # Tunnel / proxy hostnames that may not be locally resolvable
    { value: 'qhuoq-106-219-171-165.run.pinggy-free.link', normalized: 'qhuoq-106-219-171-165.run.pinggy-free.link' },
    { value: 'abc123.ngrok.io', normalized: 'abc123.ngrok.io' },
    { value: 'example.com',  normalized: 'example.com' },
  ] + (iface ? [{ value: iface[:name], normalized: iface[:addr] }] : [])

  invalid_values = [
    # Incomplete or excessive dotted-decimal (all numeric — must be valid IPv4)
    { value: '192.0.2' },
    { value: '192.0.2.0.0' },
    { value: '1.2.3.4.5' },
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
        expect(opt.valid?('qhuoq-106-219-171-165.run.pinggy-free.link')).to be_truthy
      end
    end

    context 'with interface name errors' do
      before do
        allow(NetworkInterface).to receive(:interfaces).and_raise(NetworkInterface::Error)
      end

      it 'rescues and falls back to IP/hostname checks' do
        expect(opt).to receive(:elog).with(an_instance_of(NetworkInterface::Error))
        expect(opt.valid?('192.0.2.1')).to be_truthy
      end
    end
  end

  describe '#normalize' do
    context 'with a hostname' do
      it 'returns the hostname unchanged' do
        expect(opt.normalize('qhuoq-106-219-171-165.run.pinggy-free.link')).to eq 'qhuoq-106-219-171-165.run.pinggy-free.link'
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
