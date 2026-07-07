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
        config[:msf_api][:host] ||= Defaults::RPC_HOST
        config[:msf_api][:port] ||= (config[:msf_api][:type] == 'json-rpc') ? 8081 : Defaults::RPC_PORT

        config[:msf_api][:ssl] = config[:msf_api].fetch(:ssl, Defaults::RPC_SSL)
        config[:msf_api][:auto_start_rpc] = config[:msf_api].fetch(:auto_start_rpc, true)

        config[:msf_api][:endpoint] ||= case config[:msf_api][:type]
                                        when 'json-rpc'
                                          Msf::MCP::Metasploit::JsonRpcClient::DEFAULT_ENDPOINT
                                        else
                                          Msf::MCP::Metasploit::MessagePackClient::DEFAULT_ENDPOINT
                                        end

        config[:mcp][:transport] ||= 'stdio'
        config[:mcp][:dangerous_actions] = config[:mcp].fetch(:dangerous_actions, false)

        if config[:mcp][:transport] == 'http'
          config[:mcp][:host] ||= Defaults::MCP_HOST
          config[:mcp][:port] ||= Defaults::MCP_PORT
          config[:mcp][:min_threads] ||= Msf::MCP::Server::PUMA_MIN_THREADS
          config[:mcp][:max_threads] ||= Msf::MCP::Server::PUMA_MAX_THREADS
          config[:mcp][:workers] ||= Msf::MCP::Server::PUMA_WORKERS
        end

        # auth_token: only normalize if the key was explicitly provided.
        # Absent key means "not configured" -- the application layer generates
        # a token at startup so it can decide whether to print it.
        # nil or "" becomes nil (authentication disabled); non-empty string is used as-is.
        if config[:mcp].key?(:auth_token)
          val = config[:mcp][:auth_token]
          config[:mcp][:auth_token] = nil if val.nil? || (val.is_a?(String) && val.empty?)
        end

        config[:rate_limit][:enabled] = config[:rate_limit].fetch(:enabled, true)
        config[:rate_limit][:requests_per_minute] ||= Defaults::RATE_LIMIT_REQUESTS_PER_MINUTE
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

        # MCP authentication -- env var overrides config/default
        #   unset            -- leave whatever apply_defaults established
        #   set to ""        -- nil (disable authentication)
        #   set to non-empty -- use as the bearer token
        if ENV.key?('MSF_MCP_AUTH_TOKEN')
          mcp_token = ENV['MSF_MCP_AUTH_TOKEN']
          config[:mcp][:auth_token] = mcp_token.empty? ? nil : mcp_token
        end

        # MCP Puma server tuning overrides
        config[:mcp][:min_threads] = ENV['MSF_MCP_MIN_THREADS'].to_i if ENV['MSF_MCP_MIN_THREADS']
        config[:mcp][:max_threads] = ENV['MSF_MCP_MAX_THREADS'].to_i if ENV['MSF_MCP_MAX_THREADS']
        config[:mcp][:workers] = ENV['MSF_MCP_WORKERS'].to_i if ENV['MSF_MCP_WORKERS']

        # Dangerous actions gate override
        if ENV['MSF_MCP_DANGEROUS_ACTIONS'] && !ENV['MSF_MCP_DANGEROUS_ACTIONS'].empty?
          config[:mcp][:dangerous_actions] = parse_boolean(ENV['MSF_MCP_DANGEROUS_ACTIONS'])
        end
      end

      # Parse a string value into a boolean
      #
      # @param value [String] String to parse ('true', '1', 'yes' -> true; anything else -> false)
      # @return [Boolean]
      def self.parse_boolean(value)
        %w[true 1 yes].include?(value.to_s.downcase)
      end
    end
  end
end
