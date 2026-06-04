# -*- coding: binary -*-
module Msf
module Simple

###
#
# A simplified post-exploitation module wrapper.
#
###
module Post

  include Module

  #
  # Wraps the post-exploitation module running process in a simple single
  # method.  The options hash can have the following values passed in it:
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
  # 	Whether or not the module should be run in the context of a background
  # 	job.
  #
  def self.run_simple(omod, opts = {}, &block)
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
    mod.validate

    # Initialize user interaction
    if ! opts['Quiet']
      mod.init_ui(opts['LocalInput'] || mod.user_input, opts['LocalOutput'] || mod.user_output)
    else
      mod.init_ui(nil, nil)
    end

    #
    # Disable this until we can test background stuff a little better
    #
    if(mod.passive? or opts['RunAsJob'])
      ctx = [ mod.replicant, { originating_ui: opts['OriginatingUi'] || 'console' } ]
      mod.job_id = mod.framework.jobs.start_bg_job(
        "Post: #{mod.refname}",
        ctx,
        Proc.new { |ctx_| self.job_run_proc(ctx_) },
        Proc.new { |ctx_| self.job_cleanup_proc(ctx_) }
      )
      # Propagate this back to the caller for console mgmt
      omod.job_id = mod.job_id
    else
      ctx = [ mod, { originating_ui: opts['OriginatingUi'] || 'console' } ]
      self.job_run_proc(ctx)
      self.job_cleanup_proc(ctx)
    end
  end

  #
  # Calls the class method.
  #
  def run_simple(opts = {}, &block)
    Msf::Simple::Post.run_simple(self, opts, &block)
  end

protected

  #
  # Job run proc, sets up the module and kicks it off.
  #
  # XXX: Mostly Copy/pasted from simple/auxiliary.rb
  #
  def self.job_run_proc(ctx)
    mod = ctx[0]
    lifecycle_opts = ctx[1] || {}
    execution = Msf::Reporting::Execution.start!(
      framework: mod.framework,
      mod: mod,
      originating_ui: lifecycle_opts[:originating_ui] || 'console',
      kind: Msf::Reporting::Execution::KIND_RUN
    )
    Msf::Reporting::Execution.clear_module_unhandled_exception(mod)
    Msf::Reporting::CurrentExecution.with(execution) do
      Msf::Reporting::Execution.with_phase_setup(mod) { mod.setup }
      mod.framework.events.on_module_run(mod)
      # Grab the session object since we need to fire an event for not
      # only the normal module_run event that all module types have to
      # report, but a specific event for sessions as well.
      s = mod.framework.sessions.get(mod.datastore["SESSION"])
      if s
        mod.framework.events.on_session_module_run(s, mod)
        mod.run
      else
        mod.print_error("Session not found")
        Msf::Reporting::Execution.with_phase_cleanup(mod) { mod.cleanup }
        return
      end
    rescue Msf::Post::Complete
      Msf::Reporting::Execution.with_phase_cleanup(mod) { mod.cleanup }
      return
    rescue Msf::Post::Failed => e
      mod.error = e
      mod.print_error("Post aborted due to failure: #{e.message}")
      Msf::Reporting::Execution.with_phase_cleanup(mod) { mod.cleanup }
      return
    rescue ::Timeout::Error => e
      mod.error = e
      mod.print_error("Post triggered a timeout exception")
      Msf::Reporting::Execution.with_phase_cleanup(mod) { mod.cleanup }
      return
    rescue ::Interrupt => e
      mod.error = e
      mod.print_error("Post interrupted by the console user")
      Msf::Reporting::Execution.with_phase_cleanup(mod) { mod.cleanup }
      return
    rescue ::Msf::OptionValidateError => e
      mod.error = e
      ::Msf::Ui::Formatter::OptionValidateError.print_error(mod, e)
    rescue ::Exception => e
      mod.error = e
      Msf::Reporting::Execution.mark_module_unhandled_exception(mod)
      mod.print_error("Post failed: #{e.class} #{e}")
      if(e.class.to_s != 'Msf::OptionValidateError')
        mod.print_error("Call stack:")
        e.backtrace.each do |line|
          break if line =~ /lib.msf.base.simple.post.rb/
          mod.print_error("  #{line}")
        end
      end

      elog('Post failed', error: e)
      Msf::Reporting::Execution.capture_exception!(mod, e)
      Msf::Reporting::Execution.with_phase_cleanup(mod) { mod.cleanup }

      return
    end
  ensure
    if execution
      terminal_status, failure_reason, failure_message =
        if Msf::Reporting::Execution.module_unhandled_exception?(mod)
          reason = mod.respond_to?(:fail_reason) ? mod.fail_reason : nil
          reason = nil if reason == Msf::Module::Failure::None
          [Msf::Reporting::Execution::TERMINAL_UNHANDLED_EXCEPTION, reason, mod.error&.message]
        elsif mod.error
          reason = mod.respond_to?(:fail_reason) ? mod.fail_reason : nil
          reason = nil if reason == Msf::Module::Failure::None
          [Msf::Reporting::Execution::TERMINAL_EXPECTED_FAILURE, reason, mod.error.message]
        else
          [Msf::Reporting::Execution::TERMINAL_SUCCESS, nil, nil]
        end
      Msf::Reporting::Execution.finalize!(
        execution,
        terminal_status: terminal_status,
        failure_reason: failure_reason,
        failure_message: failure_message
      )
    end
  end

  #
  # Clean up the module after the job completes.
  #
  # Copy/pasted from simple/auxiliary.rb
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
