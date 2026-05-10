# frozen_string_literal: true

module Msf::MCP
  module Tools
    ##
    # MCP Tool: Query Metasploit Database Notes
    #
    # Retrieves notes from the Metasploit database including user annotations,
    # scan results, and discovery metadata.
    #
    class NoteInfo < ::MCP::Tool
      tool_name 'msf_note_info'
      description 'Query Metasploit database for notes and annotations. '\
                  'Returns notes including host associations and metadata.'

      input_schema(

        properties: {
          workspace: {
            type: 'string',
            description: 'Workspace name (default: "default")',
            default: 'default'
          },
          type: {
            type: 'string',
            description: 'Note type (e.g. "ssl.certificate", "smb.fingerprint")'
          },
          host: {
            type: 'string',
            description: 'Host IP address to filter (e.g., "192.168.1.100")'
          },
          ports: {
            type: 'string',
            description: 'Port number or range to filter (e.g., "80" or "80-443")'
          },
          protocol: {
            type: 'string',
            description: 'Protocol to filter (tcp or udp)',
            enum: ['tcp', 'udp']
          },
          limit: {
            type: 'integer',
            description: 'Maximum number of results',
            minimum: Msf::MCP::Security::InputValidator::LIMIT_MIN,
            maximum: Msf::MCP::Security::InputValidator::LIMIT_MAX,
            default: Msf::MCP::Security::InputValidator::LIMIT_DEFAULT
          },
          offset: {
            type: 'integer',
            description: 'Number of results to skip',
            minimum: 0,
            default: 0
          }
        },
        required: [:workspace]
      )

      output_schema(
        properties: {
          metadata: {
            properties: {
              workspace: { type: 'string' },
              query_time: { type: 'number' },
              total_items: { type: 'integer' },
              returned_items: { type: 'integer' },
              limit: { type: 'integer' },
              offset: { type: 'integer' }
            }
          },
          data: {
            type: 'array',
            items: {
              properties: {
                host: { type: 'string' },
                service_name_or_port: { type: 'string' },
                note_type: { type: 'string' },
                data: { type: 'string' },
                created_at: { type: 'string' }
              }
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

      meta({ source: 'metasploit_database' })

      class << self
        include ToolHelper

        ##
        # Execute note query
        #
        # @param workspace [String] Workspace name (default: 'default')
        # @param host [String, nil] Host IP address to filter
        # @param type [String, nil] Note type to filter
        # @param ports [String, nil] Port or port range to filter
        # @param protocol [String, nil] Protocol to filter (tcp or udp)
        # @param limit [Integer] Maximum results (default: 100)
        # @param offset [Integer] Results offset (default: 0)
        # @param server_context [Hash] Server context with msf_client, rate_limiter, config
        # @return [MCP::Tool::Response] Structured response with note information
        #
        def call(workspace: 'default', host: nil, type: nil, ports: nil, protocol: nil, limit: Msf::MCP::Security::InputValidator::LIMIT_DEFAULT, offset: 0, server_context:)
          start_time = Time.now

          # Extract dependencies from server context
          msf_client = server_context[:msf_client]
          rate_limiter = server_context[:rate_limiter]

          # Check rate limit
          rate_limiter.check_rate_limit!('note_info')

          # Validate inputs
          Msf::MCP::Security::InputValidator.validate_pagination!(limit, offset)
          Msf::MCP::Security::InputValidator.validate_protocol!(protocol) if protocol
          Msf::MCP::Security::InputValidator.validate_ip_address!(host) if host
          Msf::MCP::Security::InputValidator.validate_port_range!(ports) if ports

          # Call Metasploit API
          # Note that `workspace` is optional in the MSF API, the default workspace is used if not provided.
          # The default value is sent anyway for clarity.
          options = { workspace: workspace }
          options[:address] = host if host
          options[:ntype] = type if type
          options[:ports] = ports if ports
          options[:proto] = protocol if protocol
          raw_notes = msf_client.db_notes(options)

          # Transform response
          transformed = Metasploit::ResponseTransformer.transform_notes(raw_notes)

          # Apply pagination
          #
          # Note that to get the total number of entries, we gather the entire data set and apply pagination here
          # instead of sending the limit and offset to the API call to be processed by MSF.
          # This is needed to provide accurate total_items count in the metadata.
          total_items = transformed.size
          paginated_data = transformed[offset, limit] || []

          # Build metadata
          metadata = {
            workspace: workspace,
            query_time: (Time.now - start_time).round(3),
            total_items: total_items,
            returned_items: paginated_data.size,
            limit: limit,
            offset: offset
          }

          # Return MCP response
          ::MCP::Tool::Response.new(
            [
              {
                type: 'text',
                text: JSON.generate(
                  metadata: metadata,
                  data: paginated_data
                )
              }
            ],
            structured_content: {
              metadata: metadata,
              data: paginated_data
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
