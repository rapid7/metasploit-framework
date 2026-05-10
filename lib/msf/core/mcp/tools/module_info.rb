# frozen_string_literal: true

module Msf::MCP
  module Tools
    ##
    # MCP Tool: Get Metasploit Module Information
    #
    # Retrieves detailed information about a specific Metasploit module including
    # options, targets, references, and compatibility details.
    #
    class ModuleInfo < ::MCP::Tool
      tool_name 'msf_module_info'
      description 'Retrieves detailed information, documentation, and options for a single specific Metasploit module. '\
                  'Returns comprehensive module details including options, targets, payloads, and references.'

      input_schema(
        properties: {
          type: {
            type: 'string',
            description: 'Module type (exploit, auxiliary, post, payload, etc.)',
            enum: ['exploit', 'auxiliary', 'post', 'payload', 'encoder', 'evasion', 'nop']
          },
          name: {
            type: 'string',
            description: 'Module path/name (e.g., windows/smb/ms17_010_eternalblue)',
            minLength: 1,
            maxLength: 500
          }
        },
        required: [:type, :name]
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
              # TODO: consider adding `description` fields to these properties
              type: { type: 'string' },
              name: { type: 'string' },
              fullname: { type: 'string' },
              rank: { type: 'string' },
              disclosure_date: { type: 'string' },
              description: { type: 'string' },
              license: { type: 'string' },
              filepath: { type: 'string' },
              architectures: { type: 'array', items: { type: 'string', enum: %w[
                x86 x86_64 x64 mips mipsle mipsbe mips64 mips64le ppc ppce500v2
                ppc64 ppc64le cbea cbea64 sparc sparc64 armle armbe aarch64 cmd
                php tty java ruby dalvik python nodejs firefox zarch r
                riscv32be riscv32le riscv64be riscv64le loongarch64
              ] } },
              platforms: { type: 'array', items: { type: 'string' } },
              authors: { type: 'array', items: { type: 'string' } },
              privileged: { type: 'boolean' },
              has_check_method: { type: 'boolean' },
              default_options: { type: 'object' },
              references: { type: 'array', items: { type: ['string', 'object'] } },
              targets: { type: 'object' },
              default_target: { type: 'integer' },
              stance: { type: 'string' },
              actions: { type: 'object' },
              default_action: { type: 'integer' },
              options: { type: 'object' }
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
        # Execute module info retrieval
        #
        # @param type [String] Type of module
        # @param name [String] Name/path of module
        # @param server_context [Hash] Server context with msf_client, rate_limiter, config
        # @return [MCP::Tool::Response] Structured response with module details
        #
        def call(type:, name:, server_context:)
          start_time = Time.now

          # Extract dependencies from server context
          msf_client = server_context[:msf_client]
          rate_limiter = server_context[:rate_limiter]

          # Check rate limit
          rate_limiter.check_rate_limit!('module_info')

          # Validate inputs
          Msf::MCP::Security::InputValidator.validate_module_type!(type)
          Msf::MCP::Security::InputValidator.validate_module_name!(name)

          # Call Metasploit API
          raw_module_info = msf_client.module_info(type, name)

          # Transform response
          transformed = Metasploit::ResponseTransformer.transform_module_info(raw_module_info)

          # Build metadata
          metadata = {
            query_time: (Time.now - start_time).round(3)
          }

          # Return MCP response
          ::MCP::Tool::Response.new(
            [
              {
                type: 'text',
                text: JSON.generate(
                  metadata: metadata,
                  data: transformed
                )
              }
            ],
            structured_content: {
              metadata: metadata,
              data: transformed
            }
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
