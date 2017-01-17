# -*- coding: binary -*-
module Msf
module RPC
class RPC_Job < RPC_Base

  # Returns a list of jobs.
  #
  # @return [Hash] A list of jobs (IDs and names).
  #                Each key is the job ID, and each value is the job name.
  # @example Here's how you would use this from the client:
  #  # This will return ('0' is the job ID):
  #  # {"0"=>"Exploit: windows/browser/ms14_064_ole_code_execution"
  #  rpc.call('job.list')
  def rpc_list
    res = {}
    self.framework.jobs.each do |j|
      res[j[0]] = j[1].name
    end
    res
  end

  # Stops a job.
  #
  # @param [Integer] jid Job ID.
  # @raise [Msf::RPC::Exception] A 500 response indicating an invalid job ID was given.
  # @return [Hash] A hash indicating the action was successful. It contains the following key:
  #  * 'result' [String] A successful message: 'success'
  # @example Here's how you would use this from the client:
  #  rpc.call('job.stop', 0)
  def rpc_stop(jid)
    jid = jid.to_s
    obj = self.framework.jobs[jid]
    error(500, "Invalid Job") if not obj
    self.framework.jobs.stop_job(jid)
    { "result" => "success" }
  end

  # Returns information about a job.
  #
  # @param [Integer] jid Job ID.
  # @raise [Msf::RPC::Exception] A 500 response indicating an invalid job ID was given.
  # @return [Hash] A hash that contains information about the job, such as the following (and maybe more):
  #  * 'jid' [Integer] The Job ID.
  #  * 'name' [String] The name of the job.
  #  * 'start_time' [Integer] The start time.
  #  * 'datastore' [Hash] Datastore options for the module.
  # @example Here's how you would use this from the client:
  #  rpc.call('job.info', 0)
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
