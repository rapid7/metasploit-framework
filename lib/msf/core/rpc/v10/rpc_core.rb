# -*- coding: binary -*-
module Msf
module RPC
class RPC_Core < RPC_Base

  # Returns the RPC service versions.
  #
  # @return [Hash] A hash that includes the version information:
  #  * 'version' [String] Framework version
  #  * 'ruby'    [String] Ruby version
  #  * 'api'     [String] API version
  # @example Here's how you would use this from the client:
  #  rpc.call('core.version')
  def rpc_version
    {
      "version" => ::Msf::Framework::Version,
      "ruby"    => "#{RUBY_VERSION} #{RUBY_PLATFORM} #{RUBY_RELEASE_DATE}",
      "api"     => API_VERSION
    }
  end


  # Stops the RPC service.
  #
  # @return [void]
  # @example Here's how you would use this from the client:
  #  rpc.call('core.stop')
  def rpc_stop
    self.service.stop
  end


  # Returns a global datastore option.
  #
  # @param [String] var The name of the global datastore.
  # @return [Hash] The global datastore option. If the option is not set, then the value is empty.
  # @example Here's how you would use this from the client:
  #  rpc.call('core.getg', 'GlobalSetting')
  def rpc_getg(var)
    val = framework.datastore[var]
    { var.to_s => val.to_s }
  end


  # Sets a global datastore option.
  #
  # @param [String] var The hash key of the global datastore option.
  # @param [String] val The value of the global datastore option.
  # @return [Hash] A hash indicating the action was successful. It contains the following key:
  #  * 'result' [String] The successful message: 'success'
  # @example Here's how you would use this from the client:
  #  rpc.call('core.setg', 'MyGlobal', 'foobar')
  def rpc_setg(var, val)
    framework.datastore[var] = val
    { "result" => "success" }
  end


  # Unsets a global datastore option.
  #
  # @param [String] var The global datastore option.
  # @return [Hash] A hash indicating the action was successful. It contains the following key:
  #  * 'result' [String] The successful message: 'success'
  # @example Here's how you would use this from the client:
  #  rpc.call('core.unsetg', 'MyGlobal')
  def rpc_unsetg(var)
    framework.datastore.delete(var)
    { "result" => "success" }
  end


  # Saves current framework settings.
  #
  # @return [Hash] A hash indicating the action was successful. It contains the following key:
  #  * 'result' [String] The successful message: 'success'
  # @example Here's how you would use this from the client:
  #  rpc.call('core.save')
  def rpc_save
    framework.save_config
    { "result" => "success" }
  end


  # Reloads framework modules. This will take some time to complete.
  #
  # @return [Hash] Module stats that contain the following keys:
  #  * 'exploits' [Integer] The number of exploits reloaded.
  #  * 'auxiliary' [Integer] The number of auxiliary modules reloaded.
  #  * 'post' [Integer] The number of post modules reloaded.
  #  * 'encoders' [Integer] The number of encoders reloaded.
  #  * 'nops' [Integer] The number of NOP modules reloaded.
  #  * 'payloads' [Integer] The number of payloads reloaded.
  # @example Here's how you would use this from the client:
  #  rpc.call('core.reload_modules')
  def rpc_reload_modules
    framework.modules.reload_modules
    rpc_module_stats()
  end


  # Adds a new local file system path (local to the server) as a module path. The module must be
  # accessible to the user running the Metasploit service, and contain a top-level directory for
  # each module type such as: exploits, nop, encoder, payloads, auxiliary, post. Also note that
  # this will not unload modules that were deleted from the file system that were previously loaded.
  #
  # @param [String] path The new path to load.
  # @return [Hash] Module stats that contain the following keys:
  #  * 'exploits' [Integer] The number of exploits loaded.
  #  * 'auxiliary' [Integer] The number of auxiliary modules loaded.
  #  * 'post' [Integer] The number of post modules loaded.
  #  * 'encoders' [Integer] The number of encoders loaded.
  #  * 'nops' [Integer] The number of NOP modules loaded.
  #  * 'payloads' [Integer] The number of payloads loaded.
  # @example Here's how you would use this from the client:
  #  rpc.call('core.add_module_path', '/tmp/modules/')
  def rpc_add_module_path(path)
    framework.modules.add_module_path(path)
    rpc_module_stats()
  end


  # Returns the module stats.
  #
  # @return [Hash] Module stats that contain the following keys:
  #  * 'exploits' [Integer] The number of exploits.
  #  * 'auxiliary' [Integer] The number of auxiliary modules.
  #  * 'post' [Integer] The number of post modules.
  #  * 'encoders' [Integer] The number of encoders.
  #  * 'nops' [Integer] The number of NOP modules.
  #  * 'payloads' [Integer] The number of payloads.
  # @example Here's how you would use this from the client:
  #  rpc.call('core.module_stats')
  def rpc_module_stats
    {
      'exploits'  => framework.stats.num_exploits,
      'auxiliary' => framework.stats.num_auxiliary,
      'post'      => framework.stats.num_post,
      'encoders'  => framework.stats.num_encoders,
      'nops'      => framework.stats.num_nops,
      'payloads'  => framework.stats.num_payloads
    }
  end

  # Returns a list of framework threads.
  #
  # @return [Hash] A collection of threads. Each key is the thread ID, and the value is another hash
  #                that contains the following:
  #                * 'status' [String] Thread status.
  #                * 'critical' [Boolean] Thread is critical.
  #                * 'name' [String] Thread name.
  #                * 'started' [String] Timestamp of when the thread started.
  # @example Here's how you would use this from the cient:
  #  # You will get something like this:
  #  # {0=>{"status"=>"sleep", "critical"=>false, "name"=>"StreamServerListener", "started"=>"2015-04-21 15:25:49 -0500"}}
  #  rpc.call('core.thread_list')
  def rpc_thread_list
    res = {}
    framework.threads.each_index do |i|
      t = framework.threads[i]
      next if not t
      res[i] = {
        :status   => (t.status || "dead"),
        :critical => t[:tm_crit] ? true : false,
        :name     => t[:tm_name].to_s,
        :started  => t[:tm_time].to_s
      }
    end
    res
  end

  # Kills a framework thread.
  #
  # @param [Integer] tid The thread ID to kill.
  # @return [Hash] A hash indicating the action was successful. It contains the following key:
  #  * 'result' [String] A successful message: 'success'
  # @example Here's how you would use this from the client:
  #  rpc.call('core.thread_kill', 10)
  def rpc_thread_kill(tid)
    framework.threads.kill(tid.to_i) rescue nil
    { "result" => "success" }
  end

end
end
end

