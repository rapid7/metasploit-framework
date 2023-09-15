# -*- coding:binary -*-

require 'spec_helper'

RSpec.describe Msf::OptAddressLocal do
  iface = NetworkInterface.interfaces.collect do |iface|
    ip_address = NetworkInterface.addresses(iface).values.flatten.collect { |x| x['addr'] }.select do |addr|
      IPAddr.new(addr).ipv4? && !addr[/^127.*/]
    rescue IPAddr::InvalidAddressError
      false
    end.first
    { name: iface, addr: ip_address }
  end.select { |name_addr| name_addr[:addr] }.sort_by do |name_addr|
    ip_addr = IPAddr.new(name_addr[:addr])
    [ip_addr.ipv4?, ip_addr.to_i]
  end.first

  valid_values = [
    { value: '192.0.2.0', normalized: '192.0.2.0' },
    { value: '127.0.0.1', normalized: '127.0.0.1' },
    { value: '2001:db8::', normalized: '2001:db8::' },
    { value: '::1', normalized: '::1' },
    { value: iface[:name], normalized: iface[:addr] }
  ]

  invalid_values = [
    # Too many dots
    { value: '192.0.2.0.0' },
    # Not enough
    { value: '192.0.2' },
    # Non-string values
    { value: true },
    { value: 5 },
    { value: [] },
    { value: [1, 2] },
    { value: {} },
  ]

  it_behaves_like 'an option', valid_values, invalid_values, 'address'

  let(:required_opt) { Msf::OptAddressLocal.new('LHOST', [true, 'local address', '']) }

  describe '#normalize' do
    context 'when on a darwin host' do
      context 'and multiple ipv4 and ipv6 addresses are returned' do
        let(:mock_adapter_name) { 'mock-adapter' }
        let(:darwin_addresses) do
          {
            # Darwin AF_INET6
            30 => [
              {
                'addr' => 'fe80::146f:d90e:5c71:fea4%bridge101',
                'netmask' => 'ffff:ffff:ffff:ffff::',
                'broadcast' => nil
              },
              {
                'addr' => '2001:db8::',
                'netmask' => 'ffff::',
                'broadcast' => nil
              }
            ],
            # Darwin AF_LINK
            18 => [
              {
                'addr' => '',
                'netmask' => nil,
                'broadcast' => nil
              }
            ],
            # Darwin AF_INET
            2 => [
              {
                'addr' => '233.252.1.1',
                'netmask' => '255.255.255.0',
                'broadcast' => '233.252.1.255'
              },
              {
                'addr' => '192.0.2.1',
                'netmask' => '255.255.255.0',
                'broadcast' => '192.0.2.255'
              }
            ],
          }
        end

        before(:each) do
          allow(NetworkInterface).to receive(:interfaces).and_return([mock_adapter_name])
          allow(NetworkInterface).to receive(:addresses).with(mock_adapter_name).and_return(darwin_addresses)
        end

        it 'preferences the lowest ipv4 address' do
          expect(required_opt.normalize(mock_adapter_name)).to eq '192.0.2.1'
        end
      end
    end
  end
  describe '#interfaces' do
    context 'getting errors' do
      before(:each) do
        allow(NetworkInterface).to receive(:interfaces).and_raise(NetworkInterface::Error)
      end

      it 'rescues and returns an empty array' do
        expect(required_opt).to receive(:elog).with(an_instance_of(NetworkInterface::Error))
        result = required_opt.interfaces()
        expect(result).to eq([])
      end
    end
  end
end
