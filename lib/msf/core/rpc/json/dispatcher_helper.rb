require 'msf/core/rpc'

module Msf::RPC::JSON
  module DispatcherHelper
    # Get an RPC Dispatcher for the RPC version. Creates a new instance and stores
    # it in the dispatchers hash if one does not already exist for the version.
    # @param dispatchers [Hash] hash of version Symbol - Msf::RPC::JSON::Dispatcher object pairs
    # @param version [Symbol] the RPC version
    # @param framework [Msf::Simple::Framework] Framework wrapper instance
    # @returns [Msf::RPC::JSON::Dispatcher] an RPC Dispatcher for the specified version
    def get_dispatcher(dispatchers, version, framework)
      unless dispatchers.key?(version)
        dispatchers[version] = create_dispatcher(version, framework)
      end

      dispatchers[version]
    end

    # Create an RPC Dispatcher composed of an RpcCommand for the provided version.
    # @param version [Symbol] the RPC version
    # @param framework [Msf::Simple::Framework] Framework wrapper instance
    # @returns [Msf::RPC::JSON::Dispatcher] an RPC Dispatcher for the specified version
    def create_dispatcher(version, framework)
      command = RpcCommandFactory.create(version, framework)
      dispatcher = Dispatcher.new(framework)
      dispatcher.set_command(command)

      dispatcher
    end
  end
end