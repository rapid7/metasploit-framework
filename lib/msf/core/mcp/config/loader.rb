# frozen_string_literal: true

require 'yaml'

module Msf::MCP
  module Config
    class Loader
      # Load configuration from YAML file with environment variable overrides
      #
      # @param file_path [String] Path to YAML configuration file
      # @return [Hash] Configuration hash with symbolized keys
      # @raise [ConfigurationError] If file not found or invalid YAML
      def self.load(file_path)
        unless File.exist?(file_path)
          raise ConfigurationError, "Configuration file not found: #{file_path}"
        end

        begin
          config = YAML.safe_load_file(file_path, symbolize_names: true)
        rescue Psych::SyntaxError => e
          raise ConfigurationError, "Invalid YAML syntax in #{file_path}: #{e.message}"
        end

        unless config.is_a?(Hash)
          raise ConfigurationError, "Configuration file must contain a YAML hash/dictionary"
        end

        apply_defaults(config)
        apply_env_overrides(config)
        config
      end

      # Load configuration from hash (for testing)
      #
      # @param config_hash [Hash] Configuration hash
      # @return [Hash] Configuration hash with defaults and env overrides
      def self.load_from_hash(config_hash)
        config = config_hash.dup
        apply_defaults(config)
        apply_env_overrides(config)
        config
      end


      private

      # Apply default values to configuration
      #
      # @param config [Hash] Configuration hash to modify in place
      def self.apply_defaults(config)
        config[:msf_api] ||= {}
        config[:mcp] ||= {}
        config[:rate_limit] ||= {}
        config[:logging] ||= {}

        config[:msf_api][:type] ||= 'messagepack'
        config[:msf_api][:host] ||= 'localhost'
        config[:msf_api][:port] ||= (config[:msf_api][:type] == 'json-rpc') ? 8081 : 55553

        config[:msf_api][:ssl] = config[:msf_api].fetch(:ssl, true)
        config[:msf_api][:auto_start_rpc] = config[:msf_api].fetch(:auto_start_rpc, true)

        config[:msf_api][:endpoint] ||= case config[:msf_api][:type]
                                        when 'json-rpc'
                                          Msf::MCP::Metasploit::JsonRpcClient::DEFAULT_ENDPOINT
                                        else
                                          Msf::MCP::Metasploit::MessagePackClient::DEFAULT_ENDPOINT
                                        end

        config[:mcp][:transport] ||= 'stdio'

        if config[:mcp][:transport] == 'http'
          config[:mcp][:host] ||= 'localhost'
          config[:mcp][:port] ||= 3000
        end

        config[:rate_limit][:enabled] = config[:rate_limit].fetch(:enabled, true)
        config[:rate_limit][:requests_per_minute] ||= 60
        config[:rate_limit][:burst_size] ||= 10

        config[:logging][:enabled] = config[:logging].fetch(:enabled, false)
        config[:logging][:level] ||= 'INFO'
        config[:logging][:log_file] ||= File.join(Msf::Config.log_directory, 'msfmcp.log')
        config[:logging][:sanitize] = config[:logging].fetch(:sanitize, true)
      end

      # Apply environment variable overrides
      #
      # @param config [Hash] Configuration hash to modify in place
      def self.apply_env_overrides(config)
        # Ensure nested hashes exist
        config[:msf_api] ||= {}
        config[:mcp] ||= {}

        # MSF API overrides
        config[:msf_api][:type] = ENV['MSF_API_TYPE'] if ENV['MSF_API_TYPE']
        config[:msf_api][:host] = ENV['MSF_API_HOST'] if ENV['MSF_API_HOST']
        config[:msf_api][:port] = ENV['MSF_API_PORT'].to_i if ENV['MSF_API_PORT']
        config[:msf_api][:ssl] = parse_boolean(ENV['MSF_API_SSL']) if ENV['MSF_API_SSL'] && !ENV['MSF_API_SSL'].empty?
        config[:msf_api][:endpoint] = ENV['MSF_API_ENDPOINT'] if ENV['MSF_API_ENDPOINT']
        config[:msf_api][:user] = ENV['MSF_API_USER'] if ENV['MSF_API_USER']
        config[:msf_api][:password] = ENV['MSF_API_PASSWORD'] if ENV['MSF_API_PASSWORD']
        config[:msf_api][:token] = ENV['MSF_API_TOKEN'] if ENV['MSF_API_TOKEN']
        config[:msf_api][:auto_start_rpc] = parse_boolean(ENV['MSF_AUTO_START_RPC']) if ENV['MSF_AUTO_START_RPC']

        # MCP transport override
        config[:mcp][:transport] = ENV['MSF_MCP_TRANSPORT'] if ENV['MSF_MCP_TRANSPORT']

        # MCP server network overrides
        config[:mcp][:host] = ENV['MSF_MCP_HOST'] if ENV['MSF_MCP_HOST']
        config[:mcp][:port] = ENV['MSF_MCP_PORT'].to_i if ENV['MSF_MCP_PORT']
      end

      # Parse a string value into a boolean
      #
      # @param value [String] String to parse ('true', '1', 'yes' → true; anything else → false)
      # @return [Boolean]
      def self.parse_boolean(value)
        %w[true 1 yes].include?(value.to_s.downcase)
      end
    end
  end
end
