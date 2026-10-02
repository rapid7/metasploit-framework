# -*- coding: binary -*-

require 'spec_helper'

RSpec.describe Rex::Proto::DHCP::Server do
  let(:base_hash) do
    { 'SRVHOST' => '192.168.1.1', 'NETMASK' => '255.255.255.0' }
  end

  subject(:server) { described_class.new(base_hash) }

  def dhcp_packet(message_type, mac: "\xaa\xbb\xcc\xdd\xee\xff")
    buf = +''
    buf << [Rex::Proto::DHCP::Constants::Request].pack('C')
    buf << "\x01"
    buf << [6].pack('C')
    buf << "\x00"
    buf << "\x12\x34\x56\x78"
    buf << "\x00\x00"
    buf << "\x00\x00"
    buf << "\x00\x00\x00\x00"
    buf << "\x00\x00\x00\x00"
    buf << "\x00\x00\x00\x00"
    buf << "\x00\x00\x00\x00"
    buf << mac
    buf << ("\x00" * 10)
    buf << ("\x00" * 64)
    buf << ("\x00" * 128)
    buf << Rex::Proto::DHCP::Constants::DHCPMagic
    buf << "\x35\x01" << [message_type].pack('C')
    buf << "\xff"
    buf
  end

  describe '#initialize' do
    describe 'servePXE' do
      it 'is false when FILENAME key is absent' do
        expect(server.servePXE).to be false
      end

      it 'is false when FILENAME is an empty string' do
        srv = described_class.new(base_hash.merge('FILENAME' => ''))
        expect(srv.servePXE).to be false
      end

      it 'is true when FILENAME is a non-empty string' do
        srv = described_class.new(base_hash.merge('FILENAME' => 'pxelinux.0'))
        expect(srv.servePXE).to be true
      end

      it 'is true when the PXE key is present' do
        srv = described_class.new(base_hash.merge('PXE' => true))
        expect(srv.servePXE).to be true
      end

      it 'is false when PXEONLY is false' do
        srv = described_class.new(base_hash.merge('PXEONLY' => false))
        expect(srv.servePXE).to be false
      end

      it 'is true when PXEONLY is true' do
        srv = described_class.new(base_hash.merge('PXEONLY' => true))
        expect(srv.servePXE).to be true
      end
    end
  end

  describe 'reporter callbacks via #report' do
    let(:sock) { instance_double(Rex::Socket::Udp, sendto: 1) }
    let(:events) { [] }
    let(:from) { ['0.0.0.0', 68] }
    let(:formatted_mac) { 'aa:bb:cc:dd:ee:ff' }

    let(:server_with_reporter) do
      srv = described_class.new(base_hash)
      srv.sock = sock
      srv.report { |event| events << event }
      srv
    end

    context 'on DHCPDISCOVER' do
      it 'fires :dhcp_discover with a formatted MAC string' do
        pkt = dhcp_packet(Rex::Proto::DHCP::Constants::DHCPDiscover)
        server_with_reporter.send(:dispatch_request, from, pkt)
        expect(events).to include(hash_including(type: :dhcp_discover, mac: formatted_mac))
      end

      it 'does not include an :ip key in the discover event' do
        pkt = dhcp_packet(Rex::Proto::DHCP::Constants::DHCPDiscover)
        server_with_reporter.send(:dispatch_request, from, pkt)
        discover = events.find { |e| e[:type] == :dhcp_discover }
        expect(discover).not_to have_key(:ip)
      end
    end

    context 'on DHCPREQUEST' do
      it 'fires :dhcp_request with a formatted MAC string' do
        pkt = dhcp_packet(Rex::Proto::DHCP::Constants::DHCPRequest)
        server_with_reporter.send(:dispatch_request, from, pkt)
        expect(events).to include(hash_including(type: :dhcp_request, mac: formatted_mac))
      end

      it 'includes an :ip key in the request event' do
        pkt = dhcp_packet(Rex::Proto::DHCP::Constants::DHCPRequest)
        server_with_reporter.send(:dispatch_request, from, pkt)
        request_event = events.find { |e| e[:type] == :dhcp_request }
        expect(request_event).to have_key(:ip)
      end

      it 'includes a dotted-decimal IP string after prior DISCOVER assigns one' do
        mac = "\xde\xad\xbe\xef\xca\xfe"
        discover = dhcp_packet(Rex::Proto::DHCP::Constants::DHCPDiscover, mac: mac)
        request = dhcp_packet(Rex::Proto::DHCP::Constants::DHCPRequest, mac: mac)
        server_with_reporter.send(:dispatch_request, from, discover)
        server_with_reporter.send(:dispatch_request, from, request)
        request_event = events.find { |e| e[:type] == :dhcp_request }
        expect(request_event[:ip]).to match(/\A\d+\.\d+\.\d+\.\d+\z/)
      end
    end

    context 'on an unknown message type' do
      it 'does not fire the reporter' do
        pkt = dhcp_packet(99)
        server_with_reporter.send(:dispatch_request, from, pkt)
        expect(events).to be_empty
      end
    end

    context 'when no reporter is registered' do
      it 'does not raise on DHCPDISCOVER' do
        srv = described_class.new(base_hash)
        srv.sock = sock
        pkt = dhcp_packet(Rex::Proto::DHCP::Constants::DHCPDiscover)
        expect { srv.send(:dispatch_request, from, pkt) }.not_to raise_error
      end

      it 'does not raise on DHCPREQUEST' do
        srv = described_class.new(base_hash)
        srv.sock = sock
        pkt = dhcp_packet(Rex::Proto::DHCP::Constants::DHCPRequest)
        expect { srv.send(:dispatch_request, from, pkt) }.not_to raise_error
      end
    end
  end

  describe 'MAC address formatting' do
    let(:sock) { instance_double(Rex::Socket::Udp, sendto: 1) }
    let(:events) { [] }
    let(:mac_server) do
      srv = described_class.new(base_hash)
      srv.sock = sock
      srv.report { |e| events << e }
      srv
    end

    it 'formats all-zeros MAC correctly' do
      pkt = dhcp_packet(Rex::Proto::DHCP::Constants::DHCPDiscover, mac: "\x00" * 6)
      mac_server.send(:dispatch_request, ['0.0.0.0', 68], pkt)
      expect(events.first[:mac]).to eq('00:00:00:00:00:00')
    end

    it 'formats all-FF MAC correctly' do
      pkt = dhcp_packet(Rex::Proto::DHCP::Constants::DHCPDiscover, mac: "\xff" * 6)
      mac_server.send(:dispatch_request, ['0.0.0.0', 68], pkt)
      expect(events.first[:mac]).to eq('ff:ff:ff:ff:ff:ff')
    end

    it 'zero-pads single-nibble bytes' do
      pkt = dhcp_packet(Rex::Proto::DHCP::Constants::DHCPDiscover, mac: "\x01\x02\x03\x04\x05\x06")
      mac_server.send(:dispatch_request, ['0.0.0.0', 68], pkt)
      expect(events.first[:mac]).to eq('01:02:03:04:05:06')
    end
  end
end
