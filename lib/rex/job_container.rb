# -*- coding: binary -*-
module Rex

autoload :Job, 'rex/job'

###
#
# This class contains zero or more abstract jobs that can be enumerated and
# stopped in a generic fashion.  This is used to provide a mechanism for
# keeping track of arbitrary contexts that may or may not require a dedicated
# thread.
#
###
class JobContainer < Hash

  def initialize
    self.job_id_pool = 0
  end

  #
  # Adds an already running task as a symbolic job to the container.
  #
  def add_job(name, ctx, run_proc, clean_proc)
    real_name = name
    count     = 0
    jid       = job_id_pool

    self.job_id_pool += 1

    # If we were not supplied with a job name, pick one from the hat
    if (real_name == nil)
      real_name = '#' + jid.to_s
    end

    # Find a unique job name
    while (j = self[real_name])
      real_name  = name + " #{count}"
      count     += 1
    end

    j = Job.new(self, jid, real_name, ctx, run_proc, clean_proc)

    self[jid.to_s] = j
  end

  #
  # Starts a job using the supplied name and run/clean procedures.
  #
  def start_job(name, ctx, run_proc, clean_proc = nil)
    j = add_job(name, ctx, run_proc, clean_proc)
    j.start

    j.jid
  end

  #
  # Starts a background job that doesn't call the cleanup routine or run
  # the run_proc in its own thread.  Rather, the run_proc is called
  # immediately and the clean_proc is never called until the job is removed
  # from the job container.
  #
  def start_bg_job(name, ctx, run_proc, clean_proc = nil, async = true)
    j = add_job(name, ctx, run_proc, clean_proc)
    j.start(async)

    j.jid
  end

  #
  # Stops the job with the supplied name and forces it to cleanup.  Stopping
  # the job also leads to its removal.
  #
  def stop_job(jid)
    if (j = self[jid.to_s])
      j.stop

      remove_job(j)
    end
  end

  #
  # Removes a job that was previously running.  This is typically called when
  # a job completes its task.
  #
  def remove_job(inst)
    self.delete(inst.jid.to_s)
  end

  #
  # Overrides the builtin 'each' operator to avoid the following exception on Ruby 1.9.2+
  #    "can't add a new key into hash during iteration"
  #
  def each(&block)
    list = []
    self.keys.sort.each do |sidx|
      list << [sidx, self[sidx]]
    end
    list.each(&block)
  end

protected

  attr_accessor :job_id_pool # :nodoc:

end

end

