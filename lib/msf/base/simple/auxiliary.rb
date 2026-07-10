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

    # Validate the option container state so that options will
    # be normalized
    mod.validate

    # Initialize user interaction
    if ! opts['Quiet']
      mod.init_ui(opts['LocalInput'] || mod.user_input, opts['LocalOutput'] || mod.user_output)
    else
      mod.init_ui(nil, nil)
    end

    run_uuid = Rex::Text.rand_text_alphanumeric(24)
    job_listener.waiting run_uuid
    originating_interface = opts['OriginatingInterface'] || 'console'
    ctx = [mod, run_uuid, job_listener, { originating_interface: originating_interface, kind: Msf::Reporting::Execution::KIND_RUN }]
    run_as_job = opts['RunAsJob'].nil? ? mod.passive? : opts['RunAsJob']
    if run_as_job
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
      raise ::NotImplementedError.new(Msf::Exploit::CheckCode::Unsupported.message)
    end

    # Validate the option container state so that options will
    # be normalized
    mod.validate

    run_uuid = Rex::Text.rand_text_alphanumeric(24)
    job_listener.waiting run_uuid
    originating_interface = opts['OriginatingInterface'] || 'console'
    ctx = [mod, run_uuid, job_listener, { originating_interface: originating_interface, kind: Msf::Reporting::Execution::KIND_CHECK }]

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
  def check_simple(opts = {})
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
    lifecycle_opts = ctx[3] || {}
    execution_kind = lifecycle_opts[:kind] || Msf::Reporting::Execution::KIND_RUN
    originating_interface = lifecycle_opts[:originating_interface] || 'console'
    execution = Msf::Reporting::Execution.start!(
      framework: mod.framework,
      mod: mod,
      originating_interface: originating_interface,
      kind: execution_kind
    )
    Msf::Reporting::Execution.clear_module_unhandled_exception(mod)
    last_check_code = nil
    result = nil
    failure_exception = nil
    begin
      Msf::Reporting::CurrentExecution.with(execution) do
        job_listener.start run_uuid
        mod.check_code = nil if mod.respond_to?(:check_code=)
        mod.last_vuln_attempt = nil if mod.respond_to?(:last_vuln_attempt=)
        Msf::Reporting::Execution.with_phase_setup(mod) { mod.setup }
        mod.framework.events.on_module_run(mod)
        result = block.call(mod)
        # Store the check result if the block returned a CheckCode
        mod.check_code = result if result.is_a?(Msf::Exploit::CheckCode)
        last_check_code = result if result.is_a?(Msf::Exploit::CheckCode)
      rescue Msf::Auxiliary::Complete => e
        failure_exception = e
        Msf::Reporting::Execution.with_phase_cleanup(mod) { mod.cleanup }
        return
      rescue Msf::Auxiliary::Failed => e
        mod.error = e
        failure_exception = e
        mod.print_error("Auxiliary aborted due to failure: #{e.message}")

        # The caller should have already set mod.fail_reason
        if mod.fail_reason == Msf::Module::Failure::None
          mod.fail_reason = Msf::Module::Failure::Unknown
        end
        mod.fail_detail ||= e.to_s
        Msf::Reporting::Execution.with_phase_cleanup(mod) { mod.cleanup }
        return
      rescue ::Timeout::Error => e
        mod.error = e
        failure_exception = e
        mod.fail_reason = Msf::Module::Failure::TimeoutExpired
        mod.fail_detail ||= e.to_s
        mod.print_error("Auxiliary triggered a timeout exception")
        Msf::Reporting::Execution.with_phase_cleanup(mod) { mod.cleanup }
        return
      rescue ::Interrupt => e
        mod.error = e
        failure_exception = e
        mod.fail_reason = Msf::Module::Failure::UserInterrupt
        mod.fail_detail ||= e.to_s
        mod.print_error("Stopping running against current target...")
        Msf::Reporting::Execution.with_phase_cleanup(mod) { mod.cleanup }
        mod.print_status("Control-C again to force quit all targets.")
        begin
          Rex.sleep(0.5)
        rescue ::Interrupt
          raise $!
        end
        return
      rescue ::Msf::OptionValidateError => e
        mod.error = e
        failure_exception = e
        mod.fail_reason = Msf::Module::Failure::BadConfig
        mod.fail_detail ||= e.to_s
        ::Msf::Ui::Formatter::OptionValidateError.print_error(mod, e)
      rescue ::Exception => e
        mod.error = e
        failure_exception = e
        mod.fail_reason = Msf::Module::Failure::Unknown
        mod.fail_detail ||= e.to_s
        Msf::Reporting::Execution.mark_module_unhandled_exception(mod)
        mod.print_error("Auxiliary failed: #{e.class} #{e}")
        if(e.class.to_s != 'Msf::OptionValidateError')
          mod.print_error("Call stack:")
          e.backtrace.each do |line|
            break if line =~ /lib.msf.base.simple.auxiliary.rb/
            mod.print_error("  #{line}")
          end
        end

        elog('Auxiliary failed', error: e)
        Msf::Reporting::Execution.capture_exception!(mod, e, failure_reason: mod.fail_reason)
        Msf::Reporting::Execution.with_phase_cleanup(mod) { mod.cleanup }
      end
    ensure
      # Notify the job listener exactly once. +failure_exception+ is
      # populated by every rescue branch (including +Msf::Auxiliary::Complete+,
      # which the listener historically receives via +failed+); a +nil+
      # value indicates the success path completed without raising.
      if failure_exception
        job_listener.failed(run_uuid, failure_exception, mod)
      else
        job_listener.completed(run_uuid, result, mod)
      end

      # Register an attempt in the database (an `Mdm::ExploitAttempt` (and
      # possibly an `Mdm::VulnAttempt`).
      #
      # Since auxiliary modules don't report clearly when it is a success or a
      # failure, we are calling #report_failure keeping the `mod.fail_reason`
      # value unchanged. This value is set to `Msf::Module::Failure::None` when
      # no error was reported. It should be set to another
      # `Msf::Module::Failure::*` value otherwise.
      mod.report_failure

      if execution
        terminal_status, failure_reason, failure_message =
          derive_terminal_status(mod, execution_kind, last_check_code)
        Msf::Reporting::Execution.finalize!(
          execution,
          terminal_status: terminal_status,
          failure_reason: failure_reason,
          failure_message: failure_message
        )
      end
    end
    return result
  end

  # Translate the auxiliary module's post-run state into a terminal
  # status string.
  #
  # @api private
  def self.derive_terminal_status(mod, execution_kind, last_check_code)
    unhandled = Msf::Reporting::Execution.module_unhandled_exception?(mod)

    if execution_kind == Msf::Reporting::Execution::KIND_CHECK
      if unhandled
        return [Msf::Reporting::Execution::TERMINAL_UNHANDLED_EXCEPTION, nil, mod.error&.message]
      end

      return [Msf::Reporting::Execution.terminal_status_for_check_code(last_check_code), nil, nil]
    end

    if unhandled
      reason = mod.fail_reason if mod.respond_to?(:fail_reason)
      reason = nil if reason == Msf::Module::Failure::None
      return [Msf::Reporting::Execution::TERMINAL_UNHANDLED_EXCEPTION, reason, mod.error&.message]
    end

    reason = mod.fail_reason if mod.respond_to?(:fail_reason)
    if reason && reason != Msf::Module::Failure::None
      detail = mod.respond_to?(:fail_detail) ? mod.fail_detail : nil
      [Msf::Reporting::Execution::TERMINAL_EXPECTED_FAILURE, reason, detail]
    else
      [Msf::Reporting::Execution::TERMINAL_SUCCESS, nil, nil]
    end
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
