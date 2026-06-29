# frozen_string_literal: true

module Msf::MCP
  module Tools
    ##
    # MCP Tool: List Running Module Stats
    #
    # Wraps the `module.running_stats` RPC endpoint and returns the UUIDs of
    # module runs currently in each lifecycle state (waiting, running, results).
    #
    class RunningStats < ::MCP::Tool
      tool_name 'msf_running_stats'
      description 'List the UUIDs of currently waiting, running, and completed module runs. '\
                  'Use msf_module_results with one of these UUIDs to retrieve details.'

      input_schema(properties: {})

      output_schema(
        properties: {
          metadata: {
            properties: {
              query_time: { type: 'number' }
            }
          },
          data: {
            properties: {
              waiting: { type: 'array', items: { type: 'string' } },
              running: { type: 'array', items: { type: 'string' } },
              results: { type: 'array', items: { type: 'string' } }
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
        # Execute running stats lookup
        #
        # @param server_context [Hash] Server context with msf_client, rate_limiter
        # @return [MCP::Tool::Response] Structured response with running stats
        #
        def call(server_context:)
          start_time = Time.now

          msf_client = server_context[:msf_client]
          rate_limiter = server_context[:rate_limiter]

          rate_limiter.check_rate_limit!('running_stats')

          raw_result = msf_client.running_stats

          data = {
            waiting: raw_result['waiting'] || [],
            running: raw_result['running'] || [],
            results: raw_result['results'] || []
          }

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
        end
      end
    end
  end
end
