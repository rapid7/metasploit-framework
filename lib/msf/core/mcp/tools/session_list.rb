# frozen_string_literal: true

require 'rex/stopwatch'

module Msf::MCP
  module Tools
    ##
    # MCP Tool: List Active Sessions
    #
    # Wraps the `session.list` RPC endpoint and returns a hash of active
    # framework sessions keyed by session ID.
    #
    class SessionList < ::MCP::Tool
      tool_name 'msf_session_list'
      description 'List all active Metasploit sessions. '\
                  'Returns session details including type, transport endpoints, target, and platform.'

      input_schema(properties: {})

      output_schema(
        properties: {
          metadata: {
            properties: {
              query_time: { type: 'number' },
              total_sessions: { type: 'integer' }
            }
          },
          data: { type: 'object' }
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
        # Execute session listing
        #
        # @param server_context [Hash] Server context with msf_client, rate_limiter
        # @return [MCP::Tool::Response] Structured response with sessions hash
        #
        def call(server_context:)
          msf_client = server_context[:msf_client]
          rate_limiter = server_context[:rate_limiter]

          rate_limiter.check_rate_limit!('session_list')

          raw_result, elapsed = Rex::Stopwatch.elapsed_time do
            msf_client.session_list || {}
          end

          metadata = {
            query_time: elapsed.round(3),
            total_sessions: raw_result.size
          }

          ::MCP::Tool::Response.new(
            [{ type: 'text', text: JSON.generate(metadata: metadata, data: raw_result) }],
            structured_content: { metadata: metadata, data: raw_result }
          )
        rescue Msf::MCP::Security::RateLimitExceededError => e
          tool_error_response("Rate limit exceeded: #{e.message}")
        rescue Msf::MCP::Metasploit::AuthenticationError => e
          tool_error_response("Authentication failed: #{e.message}")
        rescue Msf::MCP::Metasploit::APIError => e
          tool_error_response("Metasploit API error: #{e.message}")
        end
      end
    end
  end
end
