# frozen_string_literal: true

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
      # Message fragment emitted by Msf::Exploit::CheckCode::Unsupported when
      # a target module does not implement #check.
      UNSUPPORTED_MESSAGE_PATTERN = /module does not support check/i

      tool_name 'msf_module_check'
      description 'Run the check method of a Metasploit exploit or auxiliary module. '\
                  'Returns a job_id and run UUID; use msf_module_results to retrieve the CheckCode result.'

      input_schema(
        properties: {
          type: {
            type: 'string',
            description: 'Module type',
            enum: %w[exploit auxiliary]
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
                         'separator are also accepted (e.g. HTTP::compression, SMB::ChunkSize). ' \
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
          start_time = Time.now

          msf_client = server_context[:msf_client]
          rate_limiter = server_context[:rate_limiter]

          rate_limiter.check_rate_limit!('module_check')

          Msf::MCP::Security::InputValidator.validate_parameter!('Module type', type, %w[exploit auxiliary])
          Msf::MCP::Security::InputValidator.validate_module_name!(name)
          Msf::MCP::Security::InputValidator.validate_module_options!(options)

          # MCP deep-symbolizes JSON input; the Metasploit datastore is keyed by Strings.
          stringified_options = options.transform_keys(&:to_s)

          raw_result = msf_client.module_check(type, name, stringified_options)

          data = {
            job_id: raw_result['job_id'],
            uuid: raw_result['uuid']
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
          if e.message.to_s.match?(UNSUPPORTED_MESSAGE_PATTERN)
            metadata = { query_time: (Time.now - start_time).round(3) }
            data = { status: 'unsupported', message: 'Module does not implement a check method' }
            ::MCP::Tool::Response.new(
              [{ type: 'text', text: JSON.generate(metadata: metadata, data: data) }],
              structured_content: { metadata: metadata, data: data }
            )
          else
            tool_error_response("Metasploit API error: #{e.message}")
          end
        rescue Msf::MCP::Security::ValidationError => e
          tool_error_response(e.message)
        end
      end
    end
  end
end
