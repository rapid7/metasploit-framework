# frozen_string_literal: true

module Msf::MCP
  module Tools
    ##
    # MCP Tool: Stop an Active Session
    #
    # Wraps the `session.stop` RPC endpoint to terminate a running Metasploit
    # session.
    #
    class SessionStop < ::MCP::Tool
      tool_name 'msf_session_stop'
      description 'Stop (kill) an active Metasploit session by its session ID.'

      input_schema(
        properties: {
          session_id: {
            type: 'integer',
            description: 'Session ID to stop',
            minimum: 1
          }
        },
        required: [:session_id]
      )

      output_schema(
        properties: {
          metadata: {
            properties: {
              query_time: { type: 'number' }
            }
          },
          data: {
            properties: {
              result: { type: 'string' }
            }
          }
        },
        required: [:metadata, :data]
      )

      annotations(
        read_only_hint: false,
        idempotent_hint: false,
        destructive_hint: true
      )

      meta({ source: 'metasploit_framework' })

      class << self
        include ToolHelper

        ##
        # Stop a session
        #
        # @param session_id [Integer] Session ID
        # @param server_context [Hash] Server context with msf_client, rate_limiter
        # @return [MCP::Tool::Response] Structured response with stop result
        #
        def call(session_id:, server_context:)
          start_time = Time.now

          msf_client = server_context[:msf_client]
          rate_limiter = server_context[:rate_limiter]

          rate_limiter.check_rate_limit!('session_stop')

          Msf::MCP::Security::InputValidator.validate_session_id!(session_id)

          raw_result = msf_client.session_stop(session_id)

          data = { result: raw_result['result'] }
          metadata = { query_time: (Time.now - start_time).round(3) }

          ::MCP::Tool::Response.new(
            [{ type: 'text', text: JSON.generate(metadata: metadata, data: data) }],
            structured_content: { metadata: metadata, data: data }
          )
        rescue Msf::MCP::Security::RateLimitExceededError => e
          tool_error_response("Rate limit exceeded: #{e.message}")
        rescue Msf::MCP::Metasploit::AuthenticationError => e
          tool_error_response("Authentication failed: #{e.message}")
        rescue Msf::MCP::Metasploit::APIError => e
          tool_error_response("Metasploit API error: #{e.message}")
        rescue Msf::MCP::Security::ValidationError => e
          tool_error_response(e.message)
        end
      end
    end
  end
end
