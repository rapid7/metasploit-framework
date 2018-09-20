require 'base64'
require 'msf/core/rpc'

module Msf::RPC::JSON
  module V1_0
    class RpcCommand < ::Msf::RPC::JSON::RpcCommand
      METHOD_GROUP_SEPARATOR = '.'

      MODULE_EXECUTE_KEY = 'module.execute'
      PAYLOAD_MODULE_TYPE_KEY = 'payload'
      PAYLOAD_KEY = 'payload'

      def initialize(framework, execute_timeout: 7200)
        super(framework, execute_timeout: execute_timeout)

        # The legacy Msf::RPC::Service will not be started, however, it will be used to proxy
        # requests to existing handlers. This frees the command from having to act as the
        # service to RPC_Base subclasses and expose accessors for tokens and users.
        @legacy_rpc_service	= ::Msf::RPC::Service.new(@framework, {
            execute_timeout: @execute_timeout
        })
      end

      def register_method(method, name: nil)
        raise "#{self.class.name}##{__method__} is not implemented"
      end

      # Call method on the receiver object previously registered.
      def execute(method, params)
        result = execute_internal(method, params)

        # post process result
        result = post_process_result(result, method, params)

        result
      end

      private

      # Call method on the receiver object previously registered.
      def execute_internal(method, params)
        # parse method string
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
            return handler.send(method_name, params)
          end
        end
      end

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

      def find_handler(handlers, group, method_name)
        handler = nil
        if !handlers[group].nil? && handlers[group].respond_to?(method_name)
          handler = handlers[group]
        end

        handler
      end

      def post_process_result(result, method, params)
        if method == MODULE_EXECUTE_KEY && params.size >= 2 &&
            params[0] == PAYLOAD_MODULE_TYPE_KEY && result.key?(PAYLOAD_KEY)
          result[PAYLOAD_KEY] = Base64.strict_encode64(result[PAYLOAD_KEY])
        end

        result
      end
    end
  end
end