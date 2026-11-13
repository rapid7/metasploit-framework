require 'spec_helper'
require 'rex/post/meterpreter/client_core'

RSpec.describe Rex::Post::Meterpreter::ClientCore do

  it "should be available" do
    expect(described_class).to eq(Rex::Post::Meterpreter::ClientCore)
  end

  describe '#get_target_time' do
    subject(:sample) { client_core.get_target_time }

    let(:client_core) { described_class.new(client) }
    let(:client) { instance_double(Rex::Post::Meterpreter::Client) }
    let(:response) { instance_double(Rex::Post::Meterpreter::Packet) }
    let(:utc_ts) { 1_700_000_000 }
    let(:local_ts) { 1_700_003_600 }
    let(:sampled_at) { Time.utc(2026, 8, 11, 12) }

    before do
      allow(client).to receive(:send_request).and_return(response)
      allow(response).to receive(:get_tlv_value).with(Rex::Post::Meterpreter::TLV_TYPE_TARGET_UNIX_TS).and_return(utc_ts)
      allow(response).to receive(:get_tlv_value).with(Rex::Post::Meterpreter::TLV_TYPE_TARGET_LOCAL_UNIX_TS).and_return(local_ts)
      allow(Time).to receive(:now).and_return(sampled_at)
    end

    it 'returns nil when the target does not support the command' do
      error = Rex::Post::Meterpreter::RequestError.new(Rex::Post::Meterpreter::COMMAND_ID_CORE_GET_TARGET_TIME, 'Unsupported command')
      allow(client).to receive(:send_request).and_raise(error)

      expect(sample).to be_nil
    end

    it 'returns the target timestamps, UTC offset, and sample time' do
      expect(sample).to eq(
        target_unix_ts: utc_ts,
        target_local_ts: local_ts,
        utc_offset: 3600,
        sampled_at: sampled_at
      )
    end

    context 'when the UTC timestamp is missing' do
      let(:utc_ts) { nil }

      it 'returns nil' do
        expect(sample).to be_nil
      end
    end

    context 'when the local timestamp is missing' do
      let(:local_ts) { nil }

      it 'returns nil' do
        expect(sample).to be_nil
      end
    end

    it 'propagates request timeouts' do
      allow(client).to receive(:send_request).and_raise(Rex::TimeoutError, 'Send timed out')

      expect { sample }.to raise_error(Rex::TimeoutError, 'Send timed out')
    end
  end

  describe "#use" do

    before(:example) do
      @response = double("response")
      allow(@response).to receive(:result) { 0 }
      allow(@response).to receive(:each) { [:help] }
      @client = double("client")
      allow(@client).to receive(:binary_suffix) { ["x64.dll"] }
      allow(@client).to receive(:capabilities) { {:ssl => false, :zlib => false } }
      allow(@client).to receive(:response_timeout) { 1 }
      allow(@client).to receive(:send_packet_wait_response) { @response }
      allow(@client).to receive(:add_extension) { true }
      allow(@client).to receive(:debug_build) { false }
    end

    let(:client_core) {described_class.new(@client)}
    it 'should respond to #use' do
      expect(client_core).to respond_to(:use)
    end

    context 'with a gemified module' do
      let(:mod) {"kiwi"}
      it 'should be available' do
        expect(client_core.use(mod)).to be_truthy
      end
    end

    context 'with a local module' do
      let(:mod) {"sniffer"}
      it 'should be available' do
        expect(client_core.use(mod)).to be_truthy
      end
    end

    context 'with a missing a module' do
      let(:mod) {"eaten_by_av"}
      it 'should be available' do
        expect { client_core.use(mod) }.to raise_error(RuntimeError)
      end
    end


  end

end
