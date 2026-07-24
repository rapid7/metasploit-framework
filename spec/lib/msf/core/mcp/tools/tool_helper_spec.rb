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
end
