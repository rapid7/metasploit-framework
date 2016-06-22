# -*- coding: binary -*-
module Rex

###
#
# This class is the concrete representation of an abstract job.
#
###
class Job

  #
  # Creates an individual job instance and initializes it with the supplied
  # parameters.
  #
  def initialize(container, jid, name, ctx, run_proc, clean_proc)
    self.container  = container
    self.jid        = jid
    self.name       = name
    self.run_proc   = run_proc
    self.clean_proc = clean_proc
    self.ctx        = ctx
    self.start_time = nil
  end

  #
  # Runs the job in the context of its own thread if the async flag is false.
  # Otherwise, the job is run inline.
  #
  def start(async = false)
    self.start_time = Time.now
    if (async)
      self.job_thread = Rex::ThreadFactory.spawn("JobID(#{jid})-#{name}", false) {
        # Deschedule our thread momentarily
        ::IO.select(nil, nil, nil, 0.01)

        begin
          run_proc.call(ctx)
        ensure
          clean_proc.call(ctx)
          container.remove_job(self)
        end
      }
    else
      begin
        run_proc.call(ctx)
      rescue ::Exception
        container.stop_job(jid)
        raise $!
      end
    end
  end

  #
  # Stops the job if it's currently running and calls its cleanup procedure
  #
  def stop
    if (self.job_thread)
      self.job_thread.kill
      self.job_thread = nil
    end

    clean_proc.call(ctx) if (clean_proc)
  end

  #
  # The name of the job.
  #
  attr_reader :name

  #
  # The job identifier as assigned by the job container.
  #
  attr_reader :jid

  #
  # The time at which this job was started.
  #
  attr_reader :start_time

  #
  # Some job context.
  #
  attr_reader :ctx

protected

  attr_writer   :name #:nodoc:
  attr_writer   :jid #:nodoc:
  attr_accessor :job_thread #:nodoc:
  attr_accessor :container #:nodoc:
  attr_accessor :run_proc #:nodoc:
  attr_accessor :clean_proc #:nodoc:
  attr_writer   :ctx #:nodoc:
  attr_writer   :start_time #:nodoc:

end

end
