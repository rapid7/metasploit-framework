module Msf::RPC::JSON
  class RpcCommand
    attr_reader :framework
    attr_accessor :execute_timeout

    # Instantiate an RpcCommand.
    # @param framework [Msf::Simple::Framework] Framework wrapper instance
    # @param execute_timeout [Integer] execute timeout duration in seconds
    def initialize(framework, execute_timeout: 7200)
      @framework = framework
      @execute_timeout = execute_timeout
      @methods = {}
    end

    # Add a method to the RPC Command
    # @param method [Method] the Method
    # @param name [String] the name the method is register under. The method name is used if nil.
    # @returns [Method] the Method.
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

    # Invokes the method on the receiver object with the specified params,
    # returning the method's return value.
    # @param method [String] the RPC method name
    # @param params [Array, Hash] parameters for the RPC call
    # @raise [MethodNotFound] The method does not exist
    # @raise [Timeout::Error] The method failed to terminate in @execute_timeout seconds
    # @returns [Object] the method's return value.
    def execute(method, params)
      unless @methods.key?(method)
        raise MethodNotFound.new(method)
      end

      ::Timeout.timeout(@execute_timeout) do
        if params.nil?
          return @methods[method].call()
        elsif params.is_a?(Array)
          return @methods[method].call(*params)
        else
          return @methods[method].call(**params)
        end
      end
    end
  end
end