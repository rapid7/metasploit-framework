# frozen_string_literal: true

require 'msf/core/mcp'

RSpec.describe Msf::MCP::Tools::ToolHelper do
  # Create a test class that includes the helper inside class << self,
  # mirroring how the actual tools use it.
  let(:tool_class) do
    mod = described_class
    Class.new do
      class << self
        include Msf::MCP::Tools::ToolHelper
      end
    end
  end

  describe '#tool_error_response' do
    it 'returns an MCP::Tool::Response' do
      result = tool_class.tool_error_response('Something went wrong')
      expect(result).to be_a(::MCP::Tool::Response)
    end

    it 'sets the error flag to true' do
      result = tool_class.tool_error_response('Something went wrong')
      expect(result.error?).to be true
    end

    it 'includes the error message in the content' do
      result = tool_class.tool_error_response('Something went wrong')
      expect(result.content).to eq([{ type: 'text', text: 'Something went wrong' }])
    end

    it 'preserves the full message for authentication errors' do
      result = tool_class.tool_error_response('Authentication failed: Invalid token')
      expect(result.content.first[:text]).to eq('Authentication failed: Invalid token')
      expect(result.error?).to be true
    end

    it 'preserves the full message for API errors' do
      result = tool_class.tool_error_response('Metasploit API error: Server error')
      expect(result.content.first[:text]).to eq('Metasploit API error: Server error')
      expect(result.error?).to be true
    end

    it 'preserves the full message for rate limit errors' do
      result = tool_class.tool_error_response('Rate limit exceeded: Retry after 5 seconds.')
      expect(result.content.first[:text]).to eq('Rate limit exceeded: Retry after 5 seconds.')
      expect(result.error?).to be true
    end
  end

  describe '#dangerous_mode_required!' do
    it 'returns without raising when dangerous_actions is true' do
      expect {
        tool_class.dangerous_mode_required!(dangerous_actions: true)
      }.not_to raise_error
    end

    it 'raises DangerousModeDisabledError when dangerous_actions is false' do
      expect {
        tool_class.dangerous_mode_required!(dangerous_actions: false)
      }.to raise_error(Msf::MCP::Tools::DangerousModeDisabledError) do |error|
        expect(error.message).to match(/dangerous actions mode/i)
        expect(error.message).to include('--enable-dangerous-actions')
        expect(error.message).to include('MSF_MCP_DANGEROUS_ACTIONS')
        expect(error.message).to include('mcp.dangerous_actions')
      end
    end

    it 'raises DangerousModeDisabledError when dangerous_actions key is missing' do
      expect {
        tool_class.dangerous_mode_required!({})
      }.to raise_error(Msf::MCP::Tools::DangerousModeDisabledError)
    end

    it 'raises DangerousModeDisabledError when dangerous_actions is a truthy non-boolean value' do
      expect {
        tool_class.dangerous_mode_required!(dangerous_actions: 'true')
      }.to raise_error(Msf::MCP::Tools::DangerousModeDisabledError)

      expect {
        tool_class.dangerous_mode_required!(dangerous_actions: 1)
      }.to raise_error(Msf::MCP::Tools::DangerousModeDisabledError)
    end
  end

  describe '#with_tool_context' do
    let(:msf_client) { double('Msf::MCP::Metasploit::Client') }
    let(:rate_limiter) { double('Msf::MCP::Security::RateLimiter') }
    let(:server_context) do
      { msf_client: msf_client, rate_limiter: rate_limiter, dangerous_actions: true }
    end

    before do
      allow(rate_limiter).to receive(:check_rate_limit!)
    end

    it 'yields the msf_client from the server context to the block' do
      captured = nil
      tool_class.with_tool_context(server_context, 'tool_key') do |client|
        captured = client
      end
      expect(captured).to be(msf_client)
    end

    it 'checks the rate limit using the supplied key before yielding' do
      order = []
      allow(rate_limiter).to receive(:check_rate_limit!) { |key| order << [:rate, key] }
      tool_class.with_tool_context(server_context, 'tool_key') { order << [:yield] }
      expect(order).to eq([[:rate, 'tool_key'], [:yield]])
    end

    it 'returns the block value on success' do
      response = ::MCP::Tool::Response.new([{ type: 'text', text: 'ok' }])
      result = tool_class.with_tool_context(server_context, 'tool_key') { response }
      expect(result).to be(response)
    end

    context 'when dangerous: false (default)' do
      it 'yields regardless of the dangerous_actions flag' do
        ctx = { msf_client: msf_client, rate_limiter: rate_limiter, dangerous_actions: false }
        expect { |b| tool_class.with_tool_context(ctx, 'tool_key', &b) }.to yield_with_args(msf_client)
      end
    end

    context 'when dangerous: true' do
      it 'yields when dangerous_actions is true' do
        expect { |b| tool_class.with_tool_context(server_context, 'tool_key', dangerous: true, &b) }
          .to yield_with_args(msf_client)
      end

      it 'returns a dangerous-mode-disabled error response when dangerous_actions is false' do
        ctx = { msf_client: msf_client, rate_limiter: rate_limiter, dangerous_actions: false }
        result = tool_class.with_tool_context(ctx, 'tool_key', dangerous: true) { raise 'should not run' }
        expect(result.error?).to be true
        expect(result.content.first[:text]).to match(/dangerous actions mode/i)
      end

      it 'does not consume rate limit when dangerous mode is disabled' do
        ctx = { msf_client: msf_client, rate_limiter: rate_limiter, dangerous_actions: false }
        tool_class.with_tool_context(ctx, 'tool_key', dangerous: true) { raise 'should not run' }
        expect(rate_limiter).not_to have_received(:check_rate_limit!)
      end
    end

    context 'error mapping' do
      it 'wraps ValidationError as a tool error with the original message' do
        result = tool_class.with_tool_context(server_context, 'tool_key') do
          raise Msf::MCP::Security::ValidationError, 'bad input'
        end
        expect(result.error?).to be true
        expect(result.content.first[:text]).to eq('bad input')
      end

      it 'wraps RateLimitExceededError with a Rate-limit prefix' do
        allow(rate_limiter).to receive(:check_rate_limit!)
          .and_raise(Msf::MCP::Security::RateLimitExceededError.new(60))
        result = tool_class.with_tool_context(server_context, 'tool_key') { :never }
        expect(result.error?).to be true
        expect(result.content.first[:text]).to match(/^Rate limit exceeded:/)
      end

      it 'wraps AuthenticationError with an Authentication-failed prefix' do
        result = tool_class.with_tool_context(server_context, 'tool_key') do
          raise Msf::MCP::Metasploit::AuthenticationError, 'nope'
        end
        expect(result.error?).to be true
        expect(result.content.first[:text]).to eq('Authentication failed: nope')
      end

      it 'wraps APIError with a Metasploit-API-error prefix' do
        result = tool_class.with_tool_context(server_context, 'tool_key') do
          raise Msf::MCP::Metasploit::APIError, 'boom'
        end
        expect(result.error?).to be true
        expect(result.content.first[:text]).to eq('Metasploit API error: boom')
      end

      it 'lets unknown exceptions propagate' do
        expect do
          tool_class.with_tool_context(server_context, 'tool_key') { raise ArgumentError, 'other' }
        end.to raise_error(ArgumentError, 'other')
      end
    end
  end
end
