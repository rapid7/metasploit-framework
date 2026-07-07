# frozen_string_literal: true

require 'rex/stopwatch'

module Msf::MCP
  module Tools
    ##
    # MCP Tool: Read Output from an Interactive Session
    #
    # Wraps the `session.interactive_read` RPC endpoint. Works for meterpreter,
    # DB, SMB, LDAP, and shell/powershell session types.
    #
    class SessionRead < ::MCP::Tool
      tool_name 'msf_session_read'
      description 'Read buffered output from an interactive Metasploit session '\
                  '(meterpreter, database, SMB, LDAP, shell, powershell).'

      input_schema(
        properties: {
          session_id: {
            type: 'integer',
            description: 'Session ID to read from',
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
              data: { type: 'string' }
            }
          }
        },
        required: [:metadata, :data]
      )

      annotations(
        read_only_hint: true,
        idempotent_hint: true,
        destructive_hint: false
      )

      meta({ source: 'metasploit_framework' })

      class << self
        include ToolHelper

        ##
        # Read from an interactive session
        #
        # @param session_id [Integer] Session ID
        # @param server_context [Hash] Server context with msf_client, rate_limiter
        # @return [MCP::Tool::Response] Structured response with session output
        #
        def call(session_id:, server_context:)
          msf_client = server_context[:msf_client]
          rate_limiter = server_context[:rate_limiter]

          rate_limiter.check_rate_limit!('session_read')

          Msf::MCP::Security::InputValidator.validate_session_id!(session_id)

          raw_result, elapsed = Rex::Stopwatch.elapsed_time do
            msf_client.session_read(session_id)
          end

          data = { data: raw_result['data'].to_s }
          metadata = { query_time: elapsed.round(3) }

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
