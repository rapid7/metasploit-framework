require 'msf/core/rpc'

module Msf::RPC::JSON
  module DispatcherHelper
    def get_dispatcher(dispatchers, version, framework)
      version_sym = version.to_sym
      unless dispatchers.key?(version_sym)
        dispatchers[version_sym] = create_dispatcher(version_sym, framework)
      end

      dispatchers[version_sym]
    end

    def create_dispatcher(version, framework)
      command = RpcCommandFactory.create(version, framework)
      dispatcher = Dispatcher.new(framework)
      dispatcher.set_command(command)

      dispatcher
    end
  end
end