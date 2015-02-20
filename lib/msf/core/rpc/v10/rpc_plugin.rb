# -*- coding: binary -*-
module Msf
module RPC
class RPC_Plugin < RPC_Base

  def rpc_load(path, xopts = {})

    opts  = {}

    xopts.each do |k,v|
      if k.class == String
        opts[k.to_sym] = v
      end
    end

    if (path !~ /#{File::SEPARATOR}/)
      plugin_file_name = path

      # If the plugin isn't in the user direcotry (~/.msf3/plugins/), use the base
      path = Msf::Config.user_plugin_directory + File::SEPARATOR + plugin_file_name
      if not File.exists?( path  + ".rb" )
        # If the following "path" doesn't exist it will be caught when we attempt to load
        path = Msf::Config.plugin_directory + File::SEPARATOR + plugin_file_name
      end
    end

    begin
      if (inst = self.framework.plugins.load(path, opts))
        return 	{ "result" => "success" }
      end
    rescue ::Exception => e
      elog("Error loading plugin #{path}: #{e}\n\n#{e.backtrace.join("\n")}", src = 'core', level = 0, from = caller)
      return 	{ "result" => "failure" }
    end

  end

  def rpc_unload(name)
    self.framework.plugins.each { |plugin|
      # Unload the plugin if it matches the name we're searching for
      if (plugin.name == name)
        self.framework.plugins.unload(plugin)
        return 	{ "result" => "success" }
      end
    }
    return 	{ "result" => "failure" }

  end

  def rpc_loaded
    ret = {}
    ret[:plugins] = []
    self.framework.plugins.each do  |plugin|
      ret[:plugins] << plugin.name
    end
    ret
  end

end
end
end
