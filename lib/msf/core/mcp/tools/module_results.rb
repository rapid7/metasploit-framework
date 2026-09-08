# frozen_string_literal: true

require 'rex/stopwatch'

module Msf::MCP
  module Tools
    ##
    # MCP Tool: Retrieve Module Run Results
    #
    # Polls the `module.results` RPC endpoint with a UUID returned by
    # {ModuleExecute} or {ModuleCheck} and returns the current status.
    #
    class ModuleResults < ::MCP::Tool
      tool_name 'msf_module_results'
      description 'Retrieve the result of a previously started module run by UUID. '\
                  'Returns the run status (ready, running, completed, or errored) and any associated result data.'

      input_schema(
        properties: {
          uuid: {
            type: 'string',
            description: 'Module run UUID returned by msf_module_execute or msf_module_check',
            minLength: 24,
            maxLength: 24
          }
        },
        required: [:uuid]
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
              status: { type: 'string', enum: %w[ready running completed errored] },
              result: {},
              error: { type: 'string' }
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
        # Execute results lookup
        #
        # @param uuid [String] Module run UUID
        # @param server_context [Hash] Server context with msf_client, rate_limiter
        # @return [MCP::Tool::Response] Structured response with run status
        #
        def call(uuid:, server_context:)
          with_tool_context(server_context, 'module_results') do |msf_client|
            Msf::MCP::Security::InputValidator.validate_uuid!(uuid)

            raw_result, elapsed = Rex::Stopwatch.elapsed_time do
              msf_client.module_results(uuid)
            end

            data = raw_result.each_with_object({}) { |(k, v), h| h[k.to_sym] = v }

            metadata = { query_time: elapsed.round(3) }

            ::MCP::Tool::Response.new(
              [{ type: 'text', text: JSON.generate(metadata: metadata, data: data) }],
              structured_content: { metadata: metadata, data: data }
            )
          end
        end
      end
    end
  end
end
