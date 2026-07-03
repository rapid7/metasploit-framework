# frozen_string_literal: true

module Msf::MCP
  module Tools
    ##
    # MCP Tool: Query Metasploit Database Services
    #
    # Retrieves service information from the Metasploit database including
    # ports, protocols, and service banners.
    #
    class ServiceInfo < ::MCP::Tool
      tool_name 'msf_service_info'
      description 'Query Metasploit database for discovered services. '\
                  'Returns service information including ports, protocols, and banners.'

      input_schema(

        properties: {
          workspace: {
            type: 'string',
            description: 'Workspace name (default: "default")',
            default: 'default'
          },
          names: {
            type: 'string',
            description: 'Comma-separated service names to filter (e.g., "http,https,ssh")'
          },
          host: {
            type: 'string',
            description: 'Host IP address (e.g., "192.168.1.100")'
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
          only_up: {
            type: 'boolean',
            description: 'Filter to only return services on hosts that are up',
            default: false
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
                host_address: { type: 'string' },
                created_at: { type: 'string' },
                updated_at: { type: 'string' },
                port: { type: 'integer' },
                protocol: { type: 'string' },
                state: { type: 'string' },
                name: { type: 'string' },
                info: { type: 'string' }
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
        # Execute service query
        #
        # @param workspace [String] Workspace name (default: 'default')
        # @param names [String, nil] Comma-separated service names to filter
        # @param ports [String, nil] Port number or range to filter
        # @param host [String, nil] Host IP address
        # @param protocol [String, nil] Protocol to filter (tcp or udp)
        # @param only_up [Boolean] Filter to only return services on hosts that are up
        # @param limit [Integer] Maximum results (default: 100)
        # @param offset [Integer] Results offset (default: 0)
        # @param server_context [Hash] Server context with msf_client, rate_limiter, config
        # @return [MCP::Tool::Response] Structured response with service information
        #
        def call(workspace: 'default', names: nil, ports: nil, host: nil, protocol: nil, only_up: false, limit: Msf::MCP::Security::InputValidator::LIMIT_DEFAULT, offset: 0, server_context:)
          start_time = Time.now

          # Extract dependencies from server context
          msf_client = server_context[:msf_client]
          rate_limiter = server_context[:rate_limiter]

          # Check rate limit
          rate_limiter.check_rate_limit!('service_info')

          # Validate inputs
          Msf::MCP::Security::InputValidator.validate_pagination!(limit, offset)
          Msf::MCP::Security::InputValidator.validate_only_up!(only_up)
          Msf::MCP::Security::InputValidator.validate_protocol!(protocol) if protocol
          Msf::MCP::Security::InputValidator.validate_ip_address!(host) if host
          Msf::MCP::Security::InputValidator.validate_port_range!(ports) if ports

          # Call Metasploit API
          # Note that `workspace` is optional in the MSF API, the default workspace is used if not provided.
          # The default value is sent anyway for clarity.
          options = { workspace: workspace }
          options[:only_up] = only_up if only_up
          options[:proto] = protocol if protocol
          # The API is misleading, it only supports a single address filter, not multiple.
          options[:addresses] = host if host
          options[:ports] = ports if ports
          options[:names] = names if names
          raw_services = msf_client.db_services(options)

          # Transform response
          transformed = Metasploit::ResponseTransformer.transform_services(raw_services)

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
