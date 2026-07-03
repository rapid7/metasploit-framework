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
end
