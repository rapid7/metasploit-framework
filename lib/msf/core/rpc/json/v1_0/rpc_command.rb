require 'base64'
require 'msf/core/rpc'

module Msf::RPC::JSON
  module V1_0
    class RpcCommand < ::Msf::RPC::JSON::RpcCommand
      METHOD_GROUP_SEPARATOR = '.'

      MODULE_EXECUTE_KEY = 'module.execute'
      PAYLOAD_MODULE_TYPE_KEY = 'payload'
      PAYLOAD_KEY = 'payload'

      # Instantiate an RpcCommand.
      # @param framework [Msf::Simple::Framework] Framework wrapper instance
      # @param execute_timeout [Integer] execute timeout duration in seconds
      def initialize(framework, execute_timeout: 7200)
        super(framework, execute_timeout: execute_timeout)

        # The legacy Msf::RPC::Service will not be started, however, it will be used to proxy
        # requests to existing handlers. This frees the command from having to act as the
        # service to RPC_Base subclasses and expose accessors for tokens and users.
        @legacy_rpc_service	= ::Msf::RPC::Service.new(@framework, {
            execute_timeout: @execute_timeout
        })
      end

      # @raise [RuntimeError] The method is not implemented
      def register_method(method, name: nil)
        raise "#{self.class.name}##{__method__} is not implemented"
      end

      # Invokes the method on the receiver object with the specified params,
      # returning the method's return value.
      # @param method [String] the RPC method name
      # @param params [Array, Hash] parameters for the RPC call
      # @returns [Object] the method's return value.
      def execute(method, params)
        result = execute_internal(method, params)
        result = post_process_result(result, method, params)

        result
      end

      private

      # Internal method that invokes the method on the receiver object with
      # the specified params, returning the method's return value.
      # @param method [String] the RPC method name
      # @param params [Array, Hash] parameters for the RPC call
      # @raise [MethodNotFound] The method does not exist
      # @raise [Timeout::Error] The method failed to terminate in @execute_timeout seconds
      # @returns [Object] the method's return value.
      def execute_internal(method, params)
        group, base_method = parse_method_group(method)

        method_name = "rpc_#{base_method}"
        method_name_noauth = "rpc_#{base_method}_noauth"

        handler = (find_handler(@legacy_rpc_service.handlers, group, method_name) || find_handler(@legacy_rpc_service.handlers, group, method_name_noauth))
        if handler.nil?
          raise MethodNotFound.new(method)
        end

        if handler.respond_to?(method_name_noauth)
          method_name = method_name_noauth
        end

        ::Timeout.timeout(@execute_timeout) do
          params = prepare_params(params)
          if params.nil?
            return handler.send(method_name)
          elsif params.is_a?(Array)
            return handler.send(method_name, *params)
          else
            return handler.send(method_name, **params)
          end
        end
      end

      # Parse method string in the format "group.base_method_name".
      # @param method [String] the RPC method name
      # @returns [Array] Tuple of strings, group and base_method
      def parse_method_group(method)
        idx = method.rindex(METHOD_GROUP_SEPARATOR)
        if idx.nil?
          group = nil
          base_method = method
        else
          group = method[0..idx - 1]
          base_method = method[idx + 1..-1]
        end
        return group, base_method
      end

      # Find the concrete Msf::RPC::RPC_Base handler for the group and method name.
      # @param handlers [Hash] hash of group String - Msf::RPC::RPC_Base object pairs
      # @param group [String] the RPC group
      # @param method_name [String] the RPC method name
      # @returns [Msf::RPC::RPC_Base] concrete Msf::RPC::RPC_Base instance if one exists; otherwise, nil.
      def find_handler(handlers, group, method_name)
        handler = nil
        if !handlers[group].nil? && handlers[group].respond_to?(method_name)
          handler = handlers[group]
        end

        handler
      end

      # Prepare params for use by RPC methods by converting all hashes
      # inside of Arrays to use strings for their names (keys).
      # @param params [Object] parameters for the RPC call
      # @returns [Object] If params is an Array all hashes it contains will be
      # modified; otherwise, the object will simply pass-through.
      def prepare_params(params)
        clean_params = params
        if params.is_a?(Array)
          clean_params = params.map do |p|
            if p.is_a?(Hash)
              stringify_names(p)
            else
              p
            end
          end
        end

        clean_params
      end

      # Stringify the names (keys) in hash.
      # @param hash [Hash] input hash
      # @returns [Hash] a new hash with strings for the keys.
      def stringify_names(hash)
        JSON.parse(JSON.dump(hash), symbolize_names: false)
      end

      # Perform custom post processing of the execute result data.
      # @param result [Object] the method's return value
      # @param method [String] the RPC method name
      # @param params [Array, Hash] parameters for the RPC call
      # @returns [Object] processed method's return value
      def post_process_result(result, method, params)
        # post-process payload module result for JSON output
        if method == MODULE_EXECUTE_KEY && params.size >= 2 &&
            params[0] == PAYLOAD_MODULE_TYPE_KEY && result.key?(PAYLOAD_KEY)
          result[PAYLOAD_KEY] = Base64.strict_encode64(result[PAYLOAD_KEY])
        end

        result
      end
    end
  end
end