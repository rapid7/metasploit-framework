module Msf::RPC::JSON
  class RpcCommand
    attr_reader :framework
    attr_accessor :execute_timeout

    def initialize(framework, execute_timeout: 7200)
      @framework = framework
      @execute_timeout = execute_timeout
      @methods = {}

      $stderr.puts("Msf::RPC::JSON::RpcCommand.initialize(): @framework=#{@framework}, @framework.object_id=#{@framework.object_id}")
      $stderr.puts("Msf::RPC::JSON::RpcCommand.initialize(): @execute_timeout=#{@execute_timeout}")
      $stderr.puts("Msf::RPC::JSON::RpcCommand.initialize(): @methods=#{@methods}")
    end

    # Add a method to the RPC Command
    def register_method(method, name: nil)
      $stderr.puts("Msf::RPC::JSON::RpcCommand.register_method(): method.class=#{method.class}, method.inspect=#{method.inspect}, name=#{name}")
      if name.nil?
        if method.is_a?(Method)
          $stderr.puts("Msf::RPC::JSON::RpcCommand.register_method(): method.name=#{method.name}")
          name = method.name.to_s
        else
          name = method.to_s
        end
      end
      @methods[name] = method
    end

    # Call method on the receiver object previously registered.
    def execute(method, params)
      $stderr.puts("Msf::RPC::JSON::RpcCommand.execute(): method=#{method}, params=#{params}")
      $stderr.puts("Msf::RPC::JSON::RpcCommand.execute(): @methods.key?(method)=#{@methods.key?(method)}")
      $stderr.puts("Msf::RPC::JSON::RpcCommand.execute(): @methods[method]=#{@methods[method]}") if @methods.key?(method)

      unless @methods.key?(method)
        $stderr.puts("Msf::RPC::JSON::RpcCommand.execute(): raising MethodNotFound...")
        raise MethodNotFound.new(method)
      end

      $stderr.puts("Msf::RPC::JSON::RpcCommand.execute(): calling method_name=#{method}...")
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

      $stderr.puts("Msf::RPC::JSON::RpcCommand.prepare_params(): params=#{params}, clean_params=#{clean_params}")
      clean_params
    end

    # Returns a new hash with strings for the names (keys).
    def stringify_names(hash)
      JSON.parse(JSON.dump(hash), symbolize_names: false)
    end
  end
end