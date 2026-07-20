# frozen_string_literal: true

module Msf::MCP
  module Tools
    ##
    # MCP Tool: Search Metasploit Modules
    #
    # Searches the Metasploit Framework module database using various criteria.
    # Supports keyword search, filtering by type, platform, and pagination.
    #
    class SearchModules < ::MCP::Tool
      tool_name 'msf_search_modules'
      description 'Search Metasploit modules according to generic search terms or specific criteria. '\
                  'Returns a list of modules matching the search criteria.'

      input_schema(
        properties: {
          # TODO: improve search criteria by adding the supported key/value pair.
          # The API support things like `type:exploit platform:windows cve:CVE-2021-34527`
          # Maybe adding specific fields for type, platform, cve, etc.
          query: {
            type: 'string',
            description: 'Search query (keywords, module names, or CVE IDs)',
            minLength: 1,
            maxLength: 500
          },
          limit: {
            type: 'integer',
            description: 'Maximum number of results to return',
            minimum: Msf::MCP::Security::InputValidator::LIMIT_MIN,
            maximum: Msf::MCP::Security::InputValidator::LIMIT_MAX,
            default: Msf::MCP::Security::InputValidator::LIMIT_DEFAULT
          },
          offset: {
            type: 'integer',
            description: 'Number of results to skip (for pagination)',
            minimum: 0,
            default: 0
          }
        },
        required: [:query]
      )

      output_schema(
        properties: {
          metadata: {
            properties: {
              query: { type: 'string' },
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
                fullname: { type: 'string' },
                type: { type: 'string' },
                name: { type: 'string' },
                rank: { type: 'string' },
                disclosure_date: { type: 'string' }
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

      meta({ source: 'metasploit_framework' })

      class << self
        include ToolHelper

        ##
        # Execute module search
        #
        # @param query [String] Search query
        # @param limit [Integer] Maximum results (default: 100)
        # @param offset [Integer] Results offset (default: 0)
        # @param server_context [Hash] Server context with msf_client, rate_limiter, config
        # @return [MCP::Tool::Response] Structured response with search results
        #
        def call(query:, limit: Msf::MCP::Security::InputValidator::LIMIT_DEFAULT, offset: 0, server_context:)
          start_time = Time.now

          # Extract dependencies from server context
          msf_client = server_context[:msf_client]
          rate_limiter = server_context[:rate_limiter]

          # Check rate limit
          rate_limiter.check_rate_limit!('search_modules')

          # Validate inputs
          Msf::MCP::Security::InputValidator.validate_search_query!(query)
          Msf::MCP::Security::InputValidator.validate_pagination!(limit, offset)

          # Call Metasploit API
          raw_modules = msf_client.search_modules(query)

          # Transform response
          transformed = Metasploit::ResponseTransformer.transform_modules(raw_modules)

          # Apply pagination
          #
          # Note that to get the total number of entries, we gather the entire data set and apply pagination here
          # instead of sending the limit and offset to the API call to be processed by MSF.
          # This is needed to provide accurate total_items count in the metadata.
          total_items = transformed.size
          paginated_data = transformed[offset, limit] || []

          # Build metadata
          metadata = {
            query: query,
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
