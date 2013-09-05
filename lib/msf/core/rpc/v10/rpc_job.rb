# -*- coding: binary -*-
module Msf
module RPC
class RPC_Job < RPC_Base

  def rpc_list
    res = {}
    self.framework.jobs.each do |j|
      res[j[0]] = j[1].name
    end
    res
  end

  def rpc_stop(jid)
    obj = self.framework.jobs[jid.to_s]
    error(500, "Invalid Job") if not obj
    obj.stop
    { "result" => "success" }
  end

  def rpc_info(jid)
    obj = self.framework.jobs[jid.to_s]
    error(500, "Invalid Job") if not obj

    info = {
      :jid => obj.jid,
      :name => obj.name,
      :start_time => obj.start_time.to_i
    }

    if obj.ctx && obj.ctx[0]
      if obj.ctx[0].respond_to?(:get_resource)
        info[:uripath] = obj.ctx[0].get_resource
      end
      if obj.ctx[0].respond_to?(:datastore)
        info[:datastore] = obj.ctx[0].datastore
      end
    end

    info
  end
end
end
end
