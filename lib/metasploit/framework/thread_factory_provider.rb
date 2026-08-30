# Wraps {Msf::Framework} so that {Msf::Framework#threads} is only created on the first call to {#spawn} by
# Rex::ThreadFactory#spawn, which allows the threads used by {Msf::ThreadManager} to be created lazily.
#
# @example Setting Rex::ThreadFactory.provider and spawning threads
#   Rex::ThreadFactory.provider = Metasploit::Framework::ThreadFactoryProvider.new(framework: framework)
#   # framework.threads created here
#   Rex::ThreadFactory.spawn("name", false) { ... }
#
require 'metasploit_data_models'
class Metasploit::Framework::ThreadFactoryProvider < Metasploit::Model::Base
  #
  # Attributes
  #

  # @!attribute framework
  #   The framework managing the spawned threads.
  #
  #   @return [Msf::Framework]
  attr_accessor :framework

  # Spawns a thread monitored by {Msf::ThreadManager} in {Msf::Framework#threads}.
  #
  # (see Msf::ThreadManager#spawn)
  def spawn(name, critical, *args, &block)
    framework.threads.spawn(name, critical, *args, &block)
  end
end
