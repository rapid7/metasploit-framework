require 'msf/core/rpc'

module Msf::RPC::JSON
  module DispatcherHelper
    def get_dispatcher(dispatchers, version, framework)
      $stderr.puts("Msf::RPC::JSON::DispatcherHelper.get_dispatcher(): dispatchers=#{dispatchers}, version=#{version}, framework=#{framework}")
      version_sym = version.to_sym
      unless dispatchers.key?(version_sym)
        $stderr.puts("Msf::RPC::JSON::DispatcherHelper.get_dispatcher(): creating dispatcher for RPC version #{version}...")
        dispatchers[version_sym] = create_dispatcher(version_sym, framework)
      end

      dispatchers[version_sym]
    end

    def create_dispatcher(version, framework)
      $stderr.puts("Msf::RPC::JSON::DispatcherHelper.create_dispatcher(): version=#{version}, framework=#{framework}")
      $stderr.puts("Msf::RPC::JSON::DispatcherHelper.create_dispatcher(): creating RpcCommand...")
      command = RpcCommandFactory.create(version, framework)
      $stderr.puts("Msf::RPC::JSON::DispatcherHelper.create_dispatcher(): command=#{command}")
      $stderr.puts("Msf::RPC::JSON::DispatcherHelper.create_dispatcher(): creating Dispatcher...")
      dispatcher = Dispatcher.new(framework)
      dispatcher.set_command(command)

      dispatcher
    end
  end
end