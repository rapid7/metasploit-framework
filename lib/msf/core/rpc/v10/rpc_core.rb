# -*- coding: binary -*-
module Msf
module RPC
class RPC_Core < RPC_Base

  def rpc_version
    {
      "version" => ::Msf::Framework::Version,
      "ruby"    => "#{RUBY_VERSION} #{RUBY_PLATFORM} #{RUBY_RELEASE_DATE}",
      "api"     => API_VERSION
    }
  end

  def rpc_stop
    self.service.stop
  end

  def rpc_setg(var, val)
    framework.datastore[var] = val
    { "result" => "success" }
  end

  def rpc_unsetg(var)
    framework.datastore.delete(var)
    { "result" => "success" }
  end

  def rpc_save
    framework.save_config
    { "result" => "success" }
  end

  def rpc_reload_modules
    framework.modules.reload_modules
    rpc_module_stats()
  end

  def rpc_add_module_path(path)
    framework.modules.add_module_path(path)
    rpc_module_stats()
  end

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

  def rpc_thread_kill(tid)
    framework.threads.kill(tid.to_i) rescue nil
    { "result" => "success" }
  end

end
end
end

