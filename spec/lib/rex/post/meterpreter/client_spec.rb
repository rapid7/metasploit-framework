require 'spec_helper'
require 'rex/post/process'
require 'rex/post/meterpreter/client'

RSpec.describe Rex::Post::Meterpreter::Client do
  subject(:client) { described_class.allocate }

  describe '#send_packet_wait_response' do
    let(:packet) { Rex::Post::Meterpreter::Packet.create_request(Rex::Post::Meterpreter::COMMAND_ID_CORE_GET_TARGET_TIME) }
    let(:waiter) { instance_double(Rex::Post::Meterpreter::PacketResponseWaiter, wait: nil) }

    before do
      client.async_mode_enabled = true
      allow(client).to receive(:commands).and_return([])
      allow(client).to receive(:passive_service).and_return(true)
      allow(client).to receive(:add_response_waiter).and_return(waiter)
      allow(client).to receive(:remove_response_waiter)
      allow(client).to receive(:send_packet).and_return(1)
    end

    it 'preserves the ten-second wait used by shutdown' do
      Rex::Post::Meterpreter::ClientCore.new(client).shutdown

      expect(waiter).to have_received(:wait).with(10)
    end

    it 'preserves a caller-provided short wait for a shutdown packet' do
      shutdown_packet = Rex::Post::Meterpreter::Packet.create_request(Rex::Post::Meterpreter::COMMAND_ID_CORE_SHUTDOWN)
      client.send_packet_wait_response(shutdown_packet, 3)

      expect(waiter).to have_received(:wait).with(3)
    end

    it 'keeps the scheduling minimum for ordinary requests with a short timeout' do
      client.send_packet_wait_response(packet, 10)

      # One week, two hours of clock drift, three 60-second polls, and ten seconds.
      expect(waiter).to have_received(:wait).with(612_190)
    end

    it 'preserves a timeout longer than the scheduling minimum' do
      client.send_packet_wait_response(packet, 700_000)

      expect(waiter).to have_received(:wait).with(700_000)
    end

    it 'keeps the rapid-poll minimum while an async lease is active' do
      client.async_lease_enabled = true
      client.send_packet_wait_response(packet, 10)

      expect(waiter).to have_received(:wait).with(13)
    end

    it 'preserves the timeout when async mode is disabled' do
      client.async_mode_enabled = false
      client.send_packet_wait_response(packet, 10)

      expect(waiter).to have_received(:wait).with(10)
    end

    it 'does not wait when the caller supplies a nil timeout' do
      client.send_packet_wait_response(packet, nil)

      expect(waiter).not_to have_received(:wait)
    end
  end

  describe '#async_lease_enabled?' do
    it 'uses the top-level process clock when Rex::Post::Process is loaded' do
      expect(defined?(Rex::Post::Process)).to eq('constant')

      client.async_lease_renewed(30)

      expect(client.async_lease_enabled?).to be(true)
    end

    it 'clears an expired lease' do
      client.async_lease_enabled = true
      client.instance_variable_set(:@async_lease_deadline, ::Process.clock_gettime(::Process::CLOCK_MONOTONIC) - 1)

      expect(client.async_lease_enabled?).to be(false)
      expect(client.async_lease_enabled).to be(false)
    end
  end
end
