# -*- coding: binary -*-
module Msf
module RPC
class RPC_Plugin < RPC_Base

  # Loads a plugin.
  #
  # @param [String] path The plugin filename (without the extension). It will try to find your plugin
  #                 in either one of these directories:
  #                 * msf/plugins/
  #                 * ~/.msf4/plugins/
  # @param [Hash] xopts Options to pass to the plugin.
  # @return [Hash] A hash indicating whether the action was successful or not.
  #                It contains the following key:
  #                * 'result' [String] A value that either says 'success' or 'failure'.
  # @example Here's how you would use this from the client:
  #  # Load the nexpose plugin
  #  rpc.call('plugin.load', 'nexpose')
  def rpc_load(path, xopts = {})
    opts = {}

    xopts.each do |k, v|
      if k.class == String
        opts[k.to_sym] = v
      end
    end

    if path !~ /#{File::SEPARATOR}/
      plugin_file_name = path

      # If the plugin isn't in the user direcotry (~/.msf3/plugins/), use the base
      path = Msf::Config.user_plugin_directory + File::SEPARATOR + plugin_file_name
      if not File.exist?(path + ".rb")
        # If the following "path" doesn't exist it will be caught when we attempt to load
        path = Msf::Config.plugin_directory + File::SEPARATOR + plugin_file_name
      end
    end

    begin
      if self.framework.plugins.load(path, opts)
        return { "result" => "success" }
      end
    rescue ::Exception => e
      elog("Error loading plugin #{path}: #{e}\n\n#{e.backtrace.join("\n")}", 'core', 0, caller)
      return { "result" => "failure" }
    end

  end


  # Unloads a plugin.
  #
  # @param [String] name The plugin filename (without the extension). For example: 'nexpose'.
  # @return [Hash] A hash indicating whether the action was successful or not.
  #                It contains the following key:
  #                * 'result' [String] A value that either says 'success' or 'failure'.
  # @example Here's how you would use this from the client:
  #  rpc.call('plugin.unload', 'nexpose')
  def rpc_unload(name)
    # Find a plugin within the plugins array
    plugin = self.framework.plugins.find { |p| p.name == name }

    # Unload the plugin if it matches the name we're searching for
    if plugin
      self.framework.plugins.unload(plugin)
      return { "result" => "success" }
    end

    { "result" => "failure" }
  end


  # Returns a list of loaded plugins.
  #
  # @return [Hash] All the plugins loaded. It contains the following key:
  #                * 'plugins' [Array<string>] A list of plugin names.
  # @example Here's how you would use this from the client:
  #  rpc.call('plugin.loaded')
  def rpc_loaded
    ret = {}
    ret[:plugins] = []
    self.framework.plugins.each do |plugin|
      ret[:plugins] << plugin.name
    end
    ret
  end

end
end
end
