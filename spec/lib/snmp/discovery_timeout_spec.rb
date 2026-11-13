require 'spec_helper'
require 'snmp'

[SNMP::UDPTransport, SNMP::RexUDPTransport].each do |transport_class|
  RSpec.describe transport_class do
    let(:socket) { instance_double(UDPSocket) }

    subject(:transport) { described_class.new(socket) }

    before do
      allow(Process).to receive(:clock_gettime)
        .with(Process::CLOCK_MONOTONIC).and_return(100.0)
    end

    it 'preserves blocking receive when no timeout is supplied' do
      expect(socket).to receive(:recv).with(8000).and_return('packet')

      expect(transport.recv(8000)).to eq('packet')
    end

    it 'returns nil when the socket is not readable before the deadline' do
      expect(IO).to receive(:select)
        .with([socket], nil, nil, 1.0).and_return(nil)
      expect(socket).not_to receive(:recv_nonblock)

      expect(transport.recv(8000, 1)).to be_nil
    end

    it 'receives a packet without a blocking read after readiness' do
      expect(IO).to receive(:select)
        .with([socket], nil, nil, 1.0).and_return([[socket], [], []])
      expect(socket).to receive(:recv_nonblock)
        .with(8000, exception: false).and_return('packet')

      expect(transport.recv(8000, 1)).to eq('packet')
    end
  end
end

RSpec.describe SNMP::RexUDPTransport do
  let(:socket) { double('Rex UDP socket') }

  subject(:transport) { described_class.new(socket) }

  it 'uses the Rex bounded receive operation and returns only the payload' do
    expect(socket).to receive(:timed_recvfrom)
      .with(8000, 1).and_return(['packet', ['AF_INET', 161, '192.0.2.1', '192.0.2.1']])

    expect(transport.recv(8000, 1)).to eq('packet')
  end

  it 'returns nil when the Rex bounded receive operation times out' do
    expect(socket).to receive(:timed_recvfrom)
      .with(8000, 1).and_return(nil)

    expect(transport.recv(8000, 1)).to be_nil
  end
end

RSpec.describe SNMP::Manager do
  subject(:manager) { described_class.allocate }

  let(:host) { '192.0.2.1' }
  let(:port) { 161 }
  let(:transport) { instance_double(SNMP::RexUDPTransport) }
  let(:usm) { instance_double(SNMP::UserBasedSecurityModel) }
  let(:message) { instance_double(SNMP::V3Message) }

  before do
    manager.instance_variable_set(:@transport, transport)
    manager.instance_variable_set(:@usm, usm)
    manager.instance_variable_set(:@max_bytes, 8000)
    manager.instance_variable_set(:@timeout, 1)
    manager.instance_variable_set(:@retries, 1)
    manager.instance_variable_set(:@config, { Host: host })

    allow(Process).to receive(:clock_gettime)
      .with(Process::CLOCK_MONOTONIC).and_return(100.0)
    allow(usm).to receive(:discovery_message).and_return('discovery packet')
    allow(transport).to receive(:send)
  end

  describe '#discover_v3_engine' do
    it 'skips an unrelated packet and accepts a matching discovery response' do
      expect(transport).to receive(:send)
        .with('discovery packet', host, port).once
      allow(transport).to receive(:recv)
        .with(8000, 1.0).and_return('unrelated packet', 'matching packet')

      expect(usm).to receive(:process_discovery_response).with(
        'unrelated packet',
        expected_message_id: kind_of(Integer),
        expected_request_id: kind_of(Integer)
      ).and_return(nil)

      expect(usm).to receive(:process_discovery_response).with(
        'matching packet',
        expected_message_id: kind_of(Integer),
        expected_request_id: kind_of(Integer)
      ).and_return(message)

      expect(manager.send(:discover_v3_engine, host, port)).to be_nil
    end

    it 'retries discovery after a receive timeout' do
      expect(transport).to receive(:send)
        .with('discovery packet', host, port).twice
      allow(transport).to receive(:recv)
        .with(8000, 1.0).and_return(nil, 'matching packet')
      allow(usm).to receive(:process_discovery_response)
        .and_return(message)

      expect(manager.send(:discover_v3_engine, host, port)).to be_nil
    end

    it 'raises RequestTimeout after exhausting discovery attempts' do
      expect(transport).to receive(:send)
        .with('discovery packet', host, port).twice
      expect(transport).to receive(:recv)
        .with(8000, 1.0).twice.and_return(nil)

      expect do
        manager.send(:discover_v3_engine, host, port)
      end.to raise_error(SNMP::RequestTimeout, /SNMPv3 discovery/)
    end

    it 'does not extend the deadline when an unrelated packet arrives' do
      manager.instance_variable_set(:@retries, 0)

      allow(Process).to receive(:clock_gettime)
        .with(Process::CLOCK_MONOTONIC)
        .and_return(100.0, 100.0, 101.0)

      expect(transport).to receive(:recv)
        .with(8000, 1.0).once.and_return('unrelated packet')
      allow(usm).to receive(:process_discovery_response).and_return(nil)

      expect do
        manager.send(:discover_v3_engine, host, port)
      end.to raise_error(SNMP::RequestTimeout, /SNMPv3 discovery/)
    end
  end
end
