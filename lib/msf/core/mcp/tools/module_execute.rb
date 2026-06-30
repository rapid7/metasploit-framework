# frozen_string_literal: true

module Msf::MCP
  module Tools
    ##
    # MCP Tool: Execute a Metasploit Module
    #
    # Invokes the Metasploit Framework `module.execute` RPC endpoint to start
    # an exploit, auxiliary, post, payload, or evasion module. Returns the
    # job_id and run UUID, which can later be polled via {ModuleResults}.
    #
    class ModuleExecute < ::MCP::Tool
      tool_name 'msf_module_execute'
      description 'Execute a Metasploit module (exploit, auxiliary, post, payload, or evasion). '\
                  'Returns a job_id and run UUID; use msf_module_results to retrieve the outcome.'

      input_schema(
        properties: {
          type: {
            type: 'string',
            description: 'Module type',
            enum: %w[exploit auxiliary post payload evasion]
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
                         'names (e.g. RHOSTS, RPORT, LHOST, LPORT, PAYLOAD, TARGET, ACTION). ' \
                         'Namespaced mixin options that use the `::` separator are also accepted ' \
                         '(e.g. HTTP::compression, CMDSTAGER::FLAVOR, EXE::Custom). ' \
                         'Values must be scalars (string, integer, float, boolean, or null). ' \
                         'Example: {"RHOSTS": "192.0.2.10", "RPORT": 4444, "PAYLOAD": "windows/meterpreter/reverse_tcp"}. ' \
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
              uuid: { type: 'string' }
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
        # Execute module run
        #
        # @param type [String] Module type (exploit/auxiliary/post/payload/evasion)
        # @param name [String] Module path/name
        # @param options [Hash] Datastore options forwarded unchanged to module.execute
        # @param server_context [Hash] Server context with msf_client, rate_limiter
        # @return [MCP::Tool::Response] Structured response with job_id and uuid
        #
        def call(type:, name:, options:, server_context:)
          start_time = Time.now

          dangerous_mode_required!(server_context)

          msf_client = server_context[:msf_client]
          rate_limiter = server_context[:rate_limiter]

          rate_limiter.check_rate_limit!('module_execute')

          Msf::MCP::Security::InputValidator.validate_module_type!(type)
          Msf::MCP::Security::InputValidator.validate_module_name!(name)
          Msf::MCP::Security::InputValidator.validate_module_options!(options)

          # MCP deep-symbolizes JSON input; the Metasploit datastore is keyed by Strings.
          stringified_options = options.transform_keys(&:to_s)

          raw_result = msf_client.module_execute(type, name, stringified_options)

          data = {
            job_id: raw_result['job_id'],
            uuid: raw_result['uuid']
          }

          metadata = { query_time: (Time.now - start_time).round(3) }

          ::MCP::Tool::Response.new(
            [{ type: 'text', text: JSON.generate(metadata: metadata, data: data) }],
            structured_content: { metadata: metadata, data: data }
          )
        rescue Msf::MCP::Tools::DangerousModeDisabledError => e
          tool_error_response(e.message)
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
