# frozen_string_literal: true

require 'rex/stopwatch'

module Msf::MCP
  module Tools
    ##
    # MCP Tool: Send Input to an Interactive Session
    #
    # Wraps the `session.interactive_write` RPC endpoint. The provided data is
    # forwarded to the session for processing (meterpreter, database, SMB, LDAP,
    # shell, powershell).
    #
    class SessionWrite < ::MCP::Tool
      tool_name 'msf_session_write'
      description 'Send input data to an interactive Metasploit session '\
                  '(meterpreter, database, SMB, LDAP, shell, powershell). Use msf_session_read to retrieve output.'

      input_schema(
        properties: {
          session_id: {
            type: 'integer',
            description: 'Session ID to write to',
            minimum: 1
          },
          data: {
            type: 'string',
            description: 'Input data to send to the session',
            minLength: 1,
            maxLength: 10_000
          }
        },
        required: [:session_id, :data]
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
        # Write to an interactive session
        #
        # @param session_id [Integer] Session ID
        # @param data [String] Data to write to the session
        # @param server_context [Hash] Server context with msf_client, rate_limiter
        # @return [MCP::Tool::Response] Structured response with write result
        #
        def call(session_id:, data:, server_context:)
          with_tool_context(server_context, 'session_write', dangerous: true) do |msf_client|
            Msf::MCP::Security::InputValidator.validate_session_id!(session_id)
            Msf::MCP::Security::InputValidator.validate_session_data!(data)

            raw_result, elapsed = Rex::Stopwatch.elapsed_time do
              msf_client.session_write(session_id, data)
            end

            response_data = { result: raw_result['result'] }
            metadata = { query_time: elapsed.round(3) }

            ::MCP::Tool::Response.new(
              [{ type: 'text', text: JSON.generate(metadata: metadata, data: response_data) }],
              structured_content: { metadata: metadata, data: response_data }
            )
          end
        end
      end
    end
  end
end
