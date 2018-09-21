require 'msf/core/rpc'
require 'msf/core/rpc/json/v1_0/rpc_command'
require 'msf/core/rpc/json/v2_0/rpc_test'

module Msf::RPC::JSON
  class RpcCommandFactory
    # Create an RpcCommand for the provided version.
    # @param version [Symbol] the RPC version
    # @param framework [Msf::Simple::Framework] Framework wrapper instance
    # @raise [ArgumentError] invalid RPC version
    # @returns [RpcCommand] an RpcCommand for the specified version
    def self.create(version, framework)
      case version
      when :v1, :v1_0, :v10
        return Msf::RPC::JSON::V1_0::RpcCommand.new(framework)
      when :v2, :v2_0
        return RpcCommandFactory.create_rpc_command_v2_0(framework)
      else
        raise ArgumentError.new("invalid RPC version #{version}")
      end
    end

    # Creates an RpcCommand for a demonstration RPC version 2.0.
    # @param framework [Msf::Simple::Framework] Framework wrapper instance
    # @returns [RpcCommand] an RpcCommand for a demonstration RPC version 2.0
    def self.create_rpc_command_v2_0(framework)
      # TODO: does belong in some sort of loader class for an RPC version?
      # instantiate receiver
      rpc_test = Msf::RPC::JSON::V2_0::RpcTest.new()

      command = Msf::RPC::JSON::RpcCommand.new(framework)

      # Add class methods
      command.register_method(Msf::RPC::JSON::V2_0::RpcTest.method(:add))
      command.register_method(Msf::RPC::JSON::V2_0::RpcTest.method(:add), name: 'add_alias')
      # Add instance methods
      command.register_method(rpc_test.method(:get_instance_rand_num))
      command.register_method(rpc_test.method(:add_instance_rand_num))

      command
    end
  end
end