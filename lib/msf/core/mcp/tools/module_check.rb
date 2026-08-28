# frozen_string_literal: true

require 'rex/stopwatch'

module Msf::MCP
  module Tools
    ##
    # MCP Tool: Run a Module's Check Method
    #
    # Invokes the Metasploit Framework `module.check` RPC endpoint. Returns the
    # job_id and run UUID for polling via {ModuleResults}. When the module does
    # not implement a check method, returns a structured `status: unsupported`
    # response instead of an error.
    #
    class ModuleCheck < ::MCP::Tool
      # Module types accepted by module.check.
      CHECK_SUPPORTED_TYPES = %w[exploit auxiliary].freeze

      # Message the module.check RPC returns when a module has no check method.
      UNSUPPORTED_CHECK_MESSAGE = 'This module does not support check.'

      tool_name 'msf_module_check'
      description 'Run the check method of a Metasploit exploit or auxiliary module. '\
                  'Returns a job_id and run UUID; use msf_module_results to retrieve the CheckCode result.'

      input_schema(
        properties: {
          type: {
            type: 'string',
            description: 'Module type',
            enum: CHECK_SUPPORTED_TYPES
          },
          name: {
            type: 'string',
            description: 'Module path/name (e.g., windows/smb/ms17_010_eternalblue)',
            minLength: 1,
            maxLength: 500
          },
          options: {
            type: 'object',
            description: 'Module datastore options as a JSON object. Keys are Metasploit option ' \
                         'names (e.g. RHOSTS, RPORT). Namespaced mixin options that use the `::` ' \
                         'separator are also accepted (e.g. HTTP::compression, SMB::ChunkSize), ' \
                         'as are hyphenated identifiers (e.g. BEARER-TOKEN). ' \
                         'Values must be scalars (string, integer, float, boolean, or null). ' \
                         'Example: {"RHOSTS": "192.0.2.10", "RPORT": 445}. ' \
                         'No nested objects or arrays.',
            additionalProperties: { type: %w[string integer number boolean null] }
          }
        },
        required: [:type, :name, :options]
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
              job_id: { type: 'integer' },
              uuid: { type: 'string' },
              status: { type: 'string' },
              message: { type: 'string' }
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
        # Execute module check
        #
        # @param type [String] Module type ('exploit' or 'auxiliary')
        # @param name [String] Module path/name
        # @param options [Hash] Datastore options forwarded to module.check
        # @param server_context [Hash] Server context with msf_client, rate_limiter
        # @return [MCP::Tool::Response] Structured response with job_id and uuid,
        #   or { status: 'unsupported' } when the module has no check method
        #
        def call(type:, name:, options:, server_context:)
          with_tool_context(server_context, 'module_check', dangerous: true) do |msf_client|
            Msf::MCP::Security::InputValidator.validate_parameter!('Module type', type, CHECK_SUPPORTED_TYPES)
            Msf::MCP::Security::InputValidator.validate_module_name!(name)
            Msf::MCP::Security::InputValidator.validate_module_options!(options)

            # MCP deep-symbolizes JSON input; the Metasploit datastore is keyed by Strings.
            stringified_options = options.transform_keys(&:to_s)

            api_error = nil
            raw_result, elapsed = Rex::Stopwatch.elapsed_time do
              msf_client.module_check(type, name, stringified_options)
            rescue Msf::MCP::Metasploit::APIError => e
              api_error = e
            end

            metadata = { query_time: elapsed.round(3) }
            data =
              if api_error
                raise api_error unless api_error.message.include?(UNSUPPORTED_CHECK_MESSAGE)

                { status: 'unsupported', message: 'Module does not implement a check method' }
              else
                { job_id: raw_result['job_id'], uuid: raw_result['uuid'] }
              end

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
