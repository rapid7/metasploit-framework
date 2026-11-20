require 'spec_helper'
require 'rex/post/process'
require 'rex/post/meterpreter/client'

RSpec.describe Rex::Post::Meterpreter::HttpPacketDispatcher do
  subject(:dispatcher) do
    Object.new.extend(
      described_class,
      Rex::Post::Meterpreter::PacketDispatcher
    ).tap do |dispatcher|
      dispatcher.singleton_class.attr_accessor :last_checkin
    end
  end

  describe '#on_passive_request' do
    let(:cli) { instance_double(Rex::Proto::Http::ServerClient) }
    let(:req) { instance_double(Rex::Proto::Http::Request, method: 'POST', body: 'response') }
    let(:packet) { instance_double(Rex::Post::Meterpreter::Packet) }
    let(:order) { [] }

    before do
      allow(Rex::Post::Meterpreter::Packet).to receive(:new).with(0).and_return(packet)
      allow(packet).to receive(:add_raw).with('response')
      allow(packet).to receive(:parse_header!)
      allow(dispatcher).to receive(:decrypt_inbound_packet).with(packet).and_return(packet)
      allow(cli).to receive(:send_response) { order << :ack }
      allow(dispatcher).to receive(:dispatch_inbound_packet).with(packet) { order << :dispatch }
      allow(dispatcher).to receive(:elog)
    end

    it 'acknowledges a POST before dispatching its response packet' do
      dispatcher.send(:on_passive_request, cli, req)

      expect(order).to eq(%i[ack dispatch])
    end

    it 'logs an acknowledgment failure and still dispatches the received POST body' do
      error = IOError.new('Connection closed')
      allow(cli).to receive(:send_response) do
        order << :ack
        raise error
      end

      dispatcher.send(:on_passive_request, cli, req)

      expect(order).to eq(%i[ack dispatch])
      expect(dispatcher).to have_received(:elog).with("Exception sending a reply to the writer request #{cli.inspect}", error: error)
    end

    it 'preserves error handling for packet parsing failures' do
      error = ArgumentError.new('Invalid packet header')
      allow(packet).to receive(:parse_header!).and_raise(error)

      dispatcher.send(:on_passive_request, cli, req)

      expect(dispatcher).to have_received(:elog).with("Exception handling request: #{cli.inspect} #{req.inspect}", error: error)
    end

    it 'preserves error handling for packet dispatch failures' do
      error = RuntimeError.new('Packet dispatch failed')
      allow(dispatcher).to receive(:dispatch_inbound_packet).with(packet).and_raise(error)

      dispatcher.send(:on_passive_request, cli, req)

      expect(dispatcher).to have_received(:elog).with("Exception handling request: #{cli.inspect} #{req.inspect}", error: error)
    end
  end
end
