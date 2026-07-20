# frozen_string_literal: true

require 'forwardable'

module Msf::MCP
  module Metasploit
    # Client facade that routes to the appropriate protocol implementation
    # Supports MessagePack RPC (Metasploit's native protocol) and JSON-RPC
    class Client
      extend Forwardable

      def_delegators :@client, :authenticate, :search_modules, :module_info, :db_hosts, :db_services, :db_vulns, :db_notes, :db_creds, :db_loot, :shutdown

      ##
      # Initialize Metasploit client with explicit parameters
      #
      # @param api_type [String] API type: 'messagepack' or 'json-rpc'
      # @param host [String] Metasploit host
      # @param port [Integer] Metasploit port
      # @param endpoint [String] API endpoint path
      # @param token [String, nil] API token (for json-rpc)
      # @param ssl [Boolean] Use SSL (default: true)
      #
      def initialize(api_type:, host:, port:, endpoint: nil, token: nil, ssl: true)
        @client = create_client(api_type: api_type, host: host, port: port, endpoint: endpoint, token: token, ssl: ssl)
      end

      private

      # Create the appropriate client based on API type
      # @param api_type [String] API type: 'messagepack' or 'json-rpc'
      # @param host [String] Metasploit host
      # @param port [Integer] Metasploit port
      # @param endpoint [String] API endpoint path
      # @param token [String, nil] API token (for json-rpc)
      # @param ssl [Boolean] Use SSL (default: true)
      # @return [MessagePackClient, JsonRpcClient] Client instance
      # @raise [Error] If invalid API type specified
      def create_client(api_type:, host:, port:, endpoint: nil, token: nil, ssl: true)
        case api_type
        when 'messagepack'
          require_relative 'messagepack_client'
          MessagePackClient.new(
            host: host,
            port: port,
            endpoint: endpoint || MessagePackClient::DEFAULT_ENDPOINT,
            ssl: ssl
          )
        when 'json-rpc'
          require_relative 'jsonrpc_client'
          JsonRpcClient.new(
            host: host,
            port: port,
            endpoint: endpoint || JsonRpcClient::DEFAULT_ENDPOINT,
            ssl: ssl,
            token: token
          )
        else
          raise Error, "Invalid API type: #{api_type}"
        end
      end
    end
  end
end
