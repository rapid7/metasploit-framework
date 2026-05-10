# frozen_string_literal: true

module Msf::MCP
  module Tools
    ##
    # MCP Tool: Query Metasploit Database Hosts
    #
    # Retrieves host information from the Metasploit database including
    # IP addresses, operating systems, and discovery metadata.
    #
    class HostInfo < ::MCP::Tool
      tool_name 'msf_host_info'
      description 'Query Metasploit database for discovered hosts. '\
                  'Returns host information including IP, OS, MAC address, and metadata.'

      input_schema(
        properties: {
          workspace: {
            type: 'string',
            description: 'Workspace name (default: "default")',
            default: 'default'
          },
          addresses: {
            type: 'string',
            description: 'IP address or CIDR range to filter (e.g., "192.168.1.100" or "192.168.1.0/24")'
          },
          only_up: {
            type: 'boolean',
            description: 'Filter to only return hosts that are up',
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
        }
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
                created_at: { type: 'string' },
                address: { type: 'string' },
                mac_address: { type: 'string' },
                hostname: { type: 'string' },
                state: { type: 'string' },
                os_name: { type: 'string' },
                os_flavor: { type: 'string' },
                os_service_pack: { type: 'string' },
                os_language: { type: 'string' },
                updated_at: { type: 'string' },
                purpose: { type: 'string' },
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
        # Execute host query
        #
        # @param workspace [String] Workspace name (default: 'default')
        # @param addresses [String, nil] IP address or CIDR range to filter
        # @param only_up [Boolean] Filter to only return hosts that are up
        # @param limit [Integer] Maximum results (default: 100)
        # @param offset [Integer] Results offset (default: 0)
        # @param server_context [Hash] Server context with msf_client, rate_limiter, config
        # @return [MCP::Tool::Response] Structured response with host information
        #
        def call(workspace: 'default', addresses: nil, only_up: false, limit: Msf::MCP::Security::InputValidator::LIMIT_DEFAULT, offset: 0, server_context:)
          start_time = Time.now

          # Extract dependencies from server context
          msf_client = server_context[:msf_client]
          rate_limiter = server_context[:rate_limiter]

          # Check rate limit
          rate_limiter.check_rate_limit!('host_info')

          # Validate inputs
          Msf::MCP::Security::InputValidator.validate_only_up!(only_up)
          Msf::MCP::Security::InputValidator.validate_ip_address!(addresses) if addresses
          Msf::MCP::Security::InputValidator.validate_pagination!(limit, offset)

          # Call Metasploit API
          # Note that `workspace` is optional in the MSF API, the default workspace is used if not provided.
          # The default value is sent anyway for clarity.
          options = { workspace: workspace }
          options[:addresses] = addresses if addresses
          options[:only_up] = only_up if only_up
          raw_hosts = msf_client.db_hosts(options)

          # Transform response
          transformed = Metasploit::ResponseTransformer.transform_hosts(raw_hosts)

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
