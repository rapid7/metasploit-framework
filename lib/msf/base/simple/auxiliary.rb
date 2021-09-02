# -*- coding: binary -*-
module Msf
module Simple

###
#
# A simplified auxiliary wrapper.
#
###
module Auxiliary

  include Module

  #
  # Wraps the auxiliary process in a simple single method.  The options
  # hash can have the following values passed in it:
  #
  # Action
  #
  # 	The selected action name.
  #
  # OptionStr
  #
  # 	A string of comma separated option values that should be imported into
  # 	the datastore.
  #
  # Options
  #
  # 	A hash of values to be imported directly into the datastore.
  #
  # LocalInput
  #
  # 	The local input handle that data can be read in from.
  #
  # LocalOutput
  #
  # 	The local output through which data can be displayed.
  #
  # RunAsJob
  #
  # 	Whether or not the exploit should be run in the context of a background
  # 	job.
  #
  def self.run_simple(omod, opts = {}, job_listener: Msf::Simple::NoopJobListener.instance, &block)

    # Clone the module to prevent changes to the original instance
    mod = omod.replicant
    Msf::Simple::Framework.simplify_module(mod)
    yield(mod) if block_given?

    # Import options from the OptionStr or Option hash.
    mod._import_extra_options(opts)

    mod.datastore['ACTION'] = opts['Action'] if opts['Action']

    # Verify the ACTION
    if (mod.actions.length > 0 and not mod.action)
      raise MissingActionError, "Please use: #{mod.actions.collect {|e| e.name} * ", "}"
    end

    # Verify the options
    mod.options.validate(mod.datastore)

    # Initialize user interaction
    if ! opts['Quiet']
      mod.init_ui(opts['LocalInput'] || mod.user_input, opts['LocalOutput'] || mod.user_output)
    else
      mod.init_ui(nil, nil)
    end

    run_uuid = Rex::Text.rand_text_alphanumeric(24)
    job_listener.waiting run_uuid
    ctx = [mod, run_uuid, job_listener]
    if(mod.passive? or opts['RunAsJob'])
      mod.job_id = mod.framework.jobs.start_bg_job(
        "Auxiliary: #{mod.refname}",
        ctx,
        Proc.new { |ctx_| self.job_run_proc(ctx_, &:run) },
        Proc.new { |ctx_| self.job_cleanup_proc(ctx_) }
      )
      # Propagate this back to the caller for console mgmt
      omod.job_id = mod.job_id
      return [run_uuid, mod.job_id]
    else
      result = self.job_run_proc(ctx, &:run)
      self.job_cleanup_proc(ctx)

      return result
    end
  end

  #
  # Calls the class method.
  #
  def run_simple(opts = {}, &block)
    Msf::Simple::Auxiliary.run_simple(self, opts, &block)
  end

  #
  # Initiates a check, setting up the exploit to be used.  The following
  # options can be specified:
  #
  # LocalInput
  #
  # 	The local input handle that data can be read in from.
  #
  # LocalOutput
  #
  # 	The local output through which data can be displayed.
  #
  def self.check_simple(mod, opts, job_listener: Msf::Simple::NoopJobListener.instance)
    Msf::Simple::Framework.simplify_module(mod)

    mod._import_extra_options(opts)
    if opts['LocalInput']
      mod.init_ui(opts['LocalInput'], opts['LocalOutput'])
    end

    unless mod.has_check?
      # Bail out early if the module doesn't have check
      raise ::NoMethodError.new(Msf::Exploit::CheckCode::Unsupported.message, 'check')
    end

    # Validate the option container state so that options will
    # be normalized
    mod.validate

    run_uuid = Rex::Text.rand_text_alphanumeric(24)
    job_listener.waiting run_uuid
    ctx = [mod, run_uuid, job_listener]

    if opts['RunAsJob']
      mod.job_id = mod.framework.jobs.start_bg_job(
        "Auxiliary: #{mod.refname} check",
        ctx,
        Proc.new do |ctx_|
          self.job_run_proc(ctx_) do |m|
            m.check
          end
        end,
        Proc.new { |ctx_| self.job_cleanup_proc(ctx_) }
      )

      [run_uuid, mod.job_id]
    else
      # Run check if it exists
      result = self.job_run_proc(ctx) do |m|
        m.check
      end
      self.job_cleanup_proc(ctx)

      result
    end
  end

  #
  # Calls the class method.
  #
  def check_simple(opts)
    Msf::Simple::Auxiliary.check_simple(self, opts)
  end


protected

  #
  # Job run proc, sets up the module and kicks it off.
  #
  def self.job_run_proc(ctx, &block)
    mod = ctx[0]
    run_uuid = ctx[1]
    job_listener = ctx[2]
    begin
      begin
        job_listener.start run_uuid
        mod.setup
        mod.framework.events.on_module_run(mod)
        result = block.call(mod)
        job_listener.completed(run_uuid, result, mod)
      rescue ::Exception => e
        job_listener.failed(run_uuid, e, mod)
        raise
      end
    rescue Msf::Auxiliary::Complete
      mod.cleanup
      return
    rescue Msf::Auxiliary::Failed => e
      mod.error = e
      mod.print_error("Auxiliary aborted due to failure: #{e.message}")
      mod.cleanup
      return
    rescue ::Timeout::Error => e
      mod.error = e
      mod.print_error("Auxiliary triggered a timeout exception")
      mod.cleanup
      return
    rescue ::Interrupt => e
      mod.error = e
      mod.print_error("Stopping running against current target...")
      mod.cleanup
      mod.print_status("Control-C again to force quit all targets.")
      begin
        Rex.sleep(0.5)
      rescue ::Interrupt
        raise $!
      end
      return
    rescue ::Msf::OptionValidateError => e
      mod.error = e
      ::Msf::Ui::Formatter::OptionValidateError.print_error(mod, e)
    rescue ::Exception => e
      mod.error = e
      mod.print_error("Auxiliary failed: #{e.class} #{e}")
      if(e.class.to_s != 'Msf::OptionValidateError')
        mod.print_error("Call stack:")
        e.backtrace.each do |line|
          break if line =~ /lib.msf.base.simple.auxiliary.rb/
          mod.print_error("  #{line}")
        end
      end

      elog('Auxiliary failed', error: e)
      mod.cleanup

    end
    return result
  end

  #
  # Clean up the module after the job completes.
  #
  def self.job_cleanup_proc(ctx)
    mod = ctx[0]
    mod.framework.events.on_module_complete(mod)
    # Allow the exploit to cleanup after itself, that messy bugger.
    mod.cleanup
  end

end

end
end

