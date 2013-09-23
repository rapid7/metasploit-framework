# -*- coding: binary -*-

require 'msf/core/rpc/v10/rpc_base'

module Msf
module RPC
class RPC_Core < RPC_Base
  FORMATTED_STATUS_BY_THREAD_STATUS = {
      false => 'terminated normally',
      nil => 'terminated with exception'
  }

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

  def rpc_add_module_path(path, options={})
    framework.modules.add_path(path, options)
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

  def rpc_thread_kill(name)
    framework.threads.list.each do |thread|
      metasploit_framework_thread = thread[:metasploit_framework_thread]

      if metasploit_framework_thread.name == name
        thread.kill
        break
      end
    end

    { "result" => "success" }
  end

  def rpc_thread_list
    # ThreadManager#list uses ThreadGroup#list so it should be thread-safe
    thread_list = framework.threads.list.each_with_object([]) { |thread, thread_list|
      metasploit_framework_thread = thread[:metasploit_framework_thread]
      hash = metasploit_framework_thread.as_json

      # ThreadGroup#list will not return a dead thread, but thread can die between ThreadGroup.list returning and
      # Thread#status being run, so need to handle dead (false/nil) statuses.
      formatted_status = FORMATTED_STATUS_BY_THREAD_STATUS.fetch(thread.status, thread.status)
      hash = hash.merge(
          status: formatted_status
      )

      thread_list << hash
    }

    thread_list.sort_by! { |thread|
      thread[:name]
    }

    thread_list
  end
end
end
end

