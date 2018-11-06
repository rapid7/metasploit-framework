require 'spec_helper'

RSpec.describe RubySMB::Dispatcher::Base do
  subject(:dispatcher) { described_class.new }
  let(:session_header) { RubySMB::Nbss::SessionHeader.new }
  let(:packet) { RubySMB::SMB1::Packet::NegotiateRequest.new }

  describe '#nbss' do
    it 'creates a SessionHeader packet' do
      expect(RubySMB::Nbss::SessionHeader).to receive(:new).and_return(session_header)
      dispatcher.nbss(packet)
    end

    it 'returns the size of the packet to the packet in 4 bytes' do
      expect(dispatcher.nbss(packet)).to eq "\x00\x00\x00\x23"
    end
  end

  it 'raises NotImplementedError on #send_packet' do
    expect { dispatcher.send_packet('foo') }.to raise_error(NotImplementedError)
  end

  it 'raises NotImplementedError on #recv_packet' do
    expect { dispatcher.recv_packet }.to raise_error(NotImplementedError)
  end
end
