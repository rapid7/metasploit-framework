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
    it 'acknowledges a POST before dispatching its response packet' do
      cli = instance_double(Rex::Proto::Http::ServerClient)
      req = instance_double(Rex::Proto::Http::Request, method: 'POST', body: 'response')
      packet = instance_double(Rex::Post::Meterpreter::Packet)
      order = []

      allow(Rex::Post::Meterpreter::Packet).to receive(:new).with(0).and_return(packet)
      allow(packet).to receive(:add_raw).with('response')
      allow(packet).to receive(:parse_header!)
      allow(dispatcher).to receive(:decrypt_inbound_packet).with(packet).and_return(packet)
      allow(cli).to receive(:send_response) { order << :ack }
      allow(dispatcher).to receive(:dispatch_inbound_packet).with(packet) { order << :dispatch }

      dispatcher.send(:on_passive_request, cli, req)

      expect(order).to eq(%i[ack dispatch])
    end
  end
end
