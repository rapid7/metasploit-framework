module Msf::RPC::JSON
  class RpcCommand
    attr_reader :framework
    attr_accessor :execute_timeout

    def initialize(framework, execute_timeout: 7200)
      @framework = framework
      @execute_timeout = execute_timeout
      @methods = {}
    end

    # Add a method to the RPC Command
    def register_method(method, name: nil)
      if name.nil?
        if method.is_a?(Method)
          name = method.name.to_s
        else
          name = method.to_s
        end
      end
      @methods[name] = method
    end

    # Call method on the receiver object previously registered.
    def execute(method, params)
      unless @methods.key?(method)
        raise MethodNotFound.new(method)
      end

      ::Timeout.timeout(@execute_timeout) do
        params = prepare_params(params)
        if params.nil?
          return @methods[method].call()
        elsif params.is_a?(Array)
          return @methods[method].call(*params)
        else
          return @methods[method].call(params)
        end
      end
    end

    private

    # Prepare params for use by RPC methods by converting all hashes to use strings for their names (keys).
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
      elsif params.is_a?(Hash)
        clean_params = stringify_names(params)
      end

      clean_params
    end

    # Returns a new hash with strings for the names (keys).
    def stringify_names(hash)
      JSON.parse(JSON.dump(hash), symbolize_names: false)
    end
  end
end