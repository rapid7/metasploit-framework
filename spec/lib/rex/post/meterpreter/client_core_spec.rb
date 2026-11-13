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

  describe '#async_mode' do
    subject(:client_core) { described_class.new(client) }

    let(:client) { Rex::Post::Meterpreter::Client.allocate }
    let(:response) { instance_double(Rex::Post::Meterpreter::Packet) }
    let(:enabled) { true }

    before do
      allow(client).to receive(:send_request).and_return(response)
      allow(response).to receive(:get_tlv_value).with(Rex::Post::Meterpreter::TLV_TYPE_ASYNC_ENABLED).and_return(enabled)
    end

    it 'rejects invalid settings before sending a request and preserves the error message' do
      expect { client_core.async_mode(enabled: true, poll_interval: 9) }
        .to raise_error(Rex::ArgumentError, 'An invalid argument was specified. Poll interval must be between 10 and 86400 seconds')

      expect(client).not_to have_received(:send_request)
    end

    it 'normalizes numeric strings before validating and serializing target settings' do
      client_core.async_mode(enabled: true, poll_interval: '10', jitter: '99', work_start: '23', work_end: '0', work_days: '1')

      expect(client).to have_received(:send_request) do |request|
        expect([
          request.get_tlv_value(Rex::Post::Meterpreter::TLV_TYPE_ASYNC_POLL_INTERVAL),
          request.get_tlv_value(Rex::Post::Meterpreter::TLV_TYPE_ASYNC_POLL_JITTER),
          request.get_tlv_value(Rex::Post::Meterpreter::TLV_TYPE_ASYNC_WORK_START),
          request.get_tlv_value(Rex::Post::Meterpreter::TLV_TYPE_ASYNC_WORK_END),
          request.get_tlv_value(Rex::Post::Meterpreter::TLV_TYPE_ASYNC_WORK_DAYS)
        ]).to eq([10, 99, 23, 0, 1])
      end
    end

    it 'uses the saved target settings when options are omitted' do
      client.async_config[:poll_interval] = 120
      client_core.async_mode(enabled: true)

      expect(client).to have_received(:send_request) do |request|
        expect(request.get_tlv_value(Rex::Post::Meterpreter::TLV_TYPE_ASYNC_POLL_INTERVAL)).to eq(120)
      end
    end

    it 'leaves console-specific job validation to the console' do
      client.async_config.merge!(lease_ttl: 29, job_timeout: 28)

      expect(client_core.async_mode(enabled: true)).to eq(response)
    end

    context 'when disabling async mode' do
      let(:enabled) { false }

      it 'does not reject invalid saved polling settings' do
        client.async_config[:poll_interval] = 0

        expect(client_core.async_mode(enabled: false)).to eq(response)
      end
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
