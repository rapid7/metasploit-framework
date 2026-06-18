# -*- coding: binary -*-

require 'spec_helper'

RSpec.describe Msf::Auxiliary::UDPScanner do
  subject do
    mod = Module.new
    mod.extend described_class
    mod.instance_variable_set(:@udp_sockets, {})
    mod.instance_variable_set(:@udp_sockets_mutex, Mutex.new)
    mod.instance_variable_set(:@results, {})
    mod.define_singleton_method(:datastore) { { 'ScannerRecvQueueLimit' => 100 } }
    mod.define_singleton_method(:inside_workspace_boundary?) { |_host| true }
    allow(mod).to receive(:cleanup_udp_sockets)
    mod
  end

  # A socket whose recvfrom raises, mimicking a connected UDP socket that received an
  # ICMP port-unreachable for a closed port.
  let(:refused_socket) do
    sock = double('refused_socket')
    allow(sock).to receive(:recvfrom).and_raise(::Errno::ECONNREFUSED)
    sock
  end

  # A socket returning a valid response in the new stdlib-aligned shape:
  #   [data, [address_family, port, hostname, host_ip]]
  let(:responding_socket) do
    sock = double('responding_socket')
    allow(sock).to receive(:recvfrom).and_return(['response-data', ['AF_INET', 161, '192.0.2.5', '192.0.2.5']])
    sock
  end

  describe '#scanner_recv' do
    it 'swallows ECONNREFUSED raised by recvfrom instead of propagating it' do
      allow(::IO).to receive(:select).and_return([[refused_socket], [], []], nil)

      expect { subject.scanner_recv(0.1) }.not_to raise_error
      expect(subject.scanner_recv(0.1)).to eq(0)
      expect(subject.results).to be_empty
    end

    it 'continues processing other readable sockets after one raises ECONNREFUSED' do
      allow(::IO).to receive(:select).and_return([[refused_socket, responding_socket], [], []], nil)

      expect(subject.scanner_recv(0.1)).to eq(1)
      expect(subject.results['192.0.2.5']).to eq(['response-data'])
    end
  end
end
