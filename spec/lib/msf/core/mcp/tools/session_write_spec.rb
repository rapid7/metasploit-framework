# frozen_string_literal: true

require 'msf/core/mcp'

RSpec.describe Msf::MCP::Tools::SessionWrite do
  let(:msf_client) { double('Msf::MCP::Metasploit::Client') }
  let(:rate_limiter) { double('Msf::MCP::Security::RateLimiter') }
  let(:server_context) do
    {
      msf_client: msf_client,
      rate_limiter: rate_limiter,
      config: {},
      dangerous_actions: true
    }
  end

  before do
    allow(rate_limiter).to receive(:check_rate_limit!)
    allow(msf_client).to receive(:session_write).and_return({ 'result' => 'success' })
  end

  describe 'Tool Name' do
    it 'has the correct tool name' do
      expect(described_class.tool_name).to eq('msf_session_write')
    end
  end

  describe 'Annotations' do
    it 'is marked as destructive' do
      annotations = described_class.annotations_value
      expect(annotations.destructive_hint).to eq(true)
      expect(annotations.read_only_hint).to eq(false)
      expect(annotations.idempotent_hint).to eq(false)
    end
  end

  describe '.call' do
    it 'checks rate limit' do
      described_class.call(session_id: 1, data: 'sysinfo', server_context: server_context)
      expect(rate_limiter).to have_received(:check_rate_limit!).with('session_write')
    end

    it 'forwards session_id and data to msf_client.session_write' do
      described_class.call(session_id: 7, data: 'whoami', server_context: server_context)
      expect(msf_client).to have_received(:session_write).with(7, 'whoami')
    end

    it 'returns the success result as structured content' do
      result = described_class.call(session_id: 1, data: 'sysinfo', server_context: server_context)
      expect(result.structured_content[:data][:result]).to eq('success')
    end

    it 'rejects non-integer session_id' do
      result = described_class.call(session_id: 'abc', data: 'sysinfo', server_context: server_context)
      expect(result.error?).to be true
      expect(result.content.first[:text]).to match(/Session ID/)
    end

    it 'rejects non-string data' do
      result = described_class.call(session_id: 1, data: 12345, server_context: server_context)
      expect(result.error?).to be true
      expect(result.content.first[:text]).to match(/Session data/)
    end

    it 'rejects empty data' do
      result = described_class.call(session_id: 1, data: '', server_context: server_context)
      expect(result.error?).to be true
      expect(result.content.first[:text]).to match(/Session data/)
    end

    it 'rejects data exceeding the size cap' do
      oversized = 'A' * (Msf::MCP::Security::InputValidator::SESSION_DATA_MAX_BYTES + 1)
      result = described_class.call(session_id: 1, data: oversized, server_context: server_context)
      expect(result.error?).to be true
      expect(result.content.first[:text]).to match(/Session data/)
    end

    it 'returns a clear error response when the framework reports the session is unknown' do
      allow(msf_client).to receive(:session_write).and_raise(
        Msf::MCP::Metasploit::APIError.new('Unknown Session ID')
      )

      result = described_class.call(session_id: 9999, data: 'sysinfo', server_context: server_context)
      expect(result.error?).to be true
      expect(result.content.first[:text]).to match(/Unknown Session ID/)
    end
  end

  describe '.call with dangerous mode disabled' do
    let(:disabled_context) do
      {
        msf_client: msf_client,
        rate_limiter: rate_limiter,
        config: {},
        dangerous_actions: false
      }
    end

    it 'returns an error response when dangerous_actions is false' do
      result = described_class.call(session_id: 1, data: 'sysinfo', server_context: disabled_context)
      expect(result.error?).to be true
      expect(result.content.first[:text]).to match(/dangerous actions mode/i)
      expect(result.content.first[:text]).to include('--enable-dangerous-actions')
    end

    it 'does not call msf_client.session_write when blocked' do
      described_class.call(session_id: 1, data: 'sysinfo', server_context: disabled_context)
      expect(msf_client).not_to have_received(:session_write)
    end

    it 'does not consume rate limit when blocked' do
      described_class.call(session_id: 1, data: 'sysinfo', server_context: disabled_context)
      expect(rate_limiter).not_to have_received(:check_rate_limit!)
    end
  end
end
