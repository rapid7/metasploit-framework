require 'msf/core/rpc'

module Msf::RPC::JSON
  module DispatcherHelper
    def get_dispatcher(dispatchers, version, framework)
      unless dispatchers.key?(version)
        dispatchers[version] = create_dispatcher(version, framework)
      end

      dispatchers[version]
    end

    def create_dispatcher(version, framework)
      command = RpcCommandFactory.create(version, framework)
      dispatcher = Dispatcher.new(framework)
      dispatcher.set_command(command)

      dispatcher
    end
  end
end