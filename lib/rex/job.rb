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
    self.cleanup_mutex = Mutex.new
    self.cleaned_up = false
    self.stop_requested = false
    self.cleanup_thread = nil
  end

  # Runs cleanup at most once. Callers do not wait for an existing owner.
  # @return [Object, nil] the callback result, or nil if cleanup was claimed
  def synchronized_cleanup
    cleanup_mutex.synchronize do
      return if cleaned_up

      self.cleaned_up = true
      self.cleanup_thread = ::Thread.current
    end

    # Callbacks may stop other jobs, so never run one under the state lock.
    begin
      clean_proc.call(ctx) if clean_proc
    ensure
      cleanup_mutex.synchronize do
        self.cleanup_thread = nil
        # A run procedure may call cleanup itself. Defer its cancellation until
        # the callback finishes; workers already unwinding have cleared this slot.
        if stop_requested && job_thread == ::Thread.current
          self.job_thread = nil
          ::Thread.current.kill
        end
      end
    end
  end

  #
  # Runs the job in its own thread if async is true, or inline otherwise.
  # @param async [Boolean] whether to spawn a worker
  # @return [Thread, Object] the worker, or the inline run procedure's result
  #
  def start(async = false)
    self.start_time = ::Time.now
    if (async)
      worker = Rex::ThreadFactory.spawn("JobID(#{jid})-#{name}", false) {
        # Deschedule our thread momentarily
        ::IO.select(nil, nil, nil, 0.01)

        begin
          should_run = cleanup_mutex.synchronize do
            unless cleaned_up || stop_requested
              # The worker can run before spawn returns to its caller.
              self.job_thread = ::Thread.current
              true
            end
          end
          run_proc.call(ctx) if should_run
        ensure
          # This worker is unwinding, so stop must not interrupt its cleanup.
          cleanup_mutex.synchronize { self.job_thread = nil if job_thread == ::Thread.current }
          synchronized_cleanup
          container.remove_job(self)
        end
      }
      worker
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
  # unless another thread has already claimed cleanup. Existing cleanup is
  # allowed to finish without waiting for it here.
  # @return [Object, nil] the cleanup result if claimed here, or nil otherwise
  #
  def stop
    # Prevent worker admission even if the factory has not published a thread.
    # Serialize cancellation with claiming cleanup, not with the callback.
    cleanup_mutex.synchronize do
      self.stop_requested = true
      if job_thread && job_thread != cleanup_thread
        job_thread.kill
        self.job_thread = nil
      end
    end

    synchronized_cleanup
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
  attr_accessor :cleanup_mutex #:nodoc:
  attr_accessor :cleaned_up #:nodoc:
  attr_accessor :stop_requested # :nodoc:
  attr_accessor :cleanup_thread # :nodoc:

end

end
