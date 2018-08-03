# -*- coding: binary -*-

require 'msf/base'

module Msf
module Simple

module Evasion
  include Module

  def self.run_simple(omod, opts = {}, &block)
    evasion_module = omod.replicant
    Msf::Simple::Framework.simplify_module(evasion_module, false)
    yield(evasion_module) if block_given?
    evasion_module._import_extra_options(opts)
    evasion_module.options.validate(evasion_module.datastore)

    if ! opts['Quiet']
      evasion_module.init_ui(opts['LocalInput'] || evasion_module.user_input, opts['LocalOutput'] || evasion_module.user_output)
    else
      evasion_module.init_ui(nil, nil)
    end

    if opts['RunAsJob']
      ctx = [ evasion_module.replicant ]
      evasion_module.job_id = evasion_module.framework.jobs.start_bg_job(
        "Evasion: #{evasion_module.refname}",
        ctx,
        Proc.new { |ctx_| self.job_run_proc(ctx_) },
        Proc.new { |ctx_| self.job_cleanup_proc(ctx_) }
      )
      # Propagate this back to the caller for console mgmt
      evasion_module.job_id = evasion_module.job_id
    else
      ctx = [ evasion_module ]
      self.job_run_proc(ctx)
      self.job_cleanup_proc(ctx)
    end
  end

  def run_simple(opts = {}, &block)
    Msf::Simple::Evasion.run_simple(self, opts, &block)
  end

  def self.job_run_proc(ctx)
    evasion_module = ctx[0]
    begin
      evasion_module.setup
      evasion_module.framework.events.on_module_run(evasion_module)
      evasion_module.run
    rescue Msf::Evasion::Complete
      evasion_module.cleanup
      return
    rescue Msf::Evasion::Failed => e
      evasion_module.error = e
      evasion_module.print_error("Evasion aborted due to failure: #{e.message}")
      evasion_module.cleanup
      return
    rescue ::Interrupt => e
      evasion_module.error = e
      evasion_module.print_error("Evasion interrupted by the console user")
      evasion_module.cleanup
      return
    rescue ::Exception => e
      evasion_module.error = e
      evasion_module.print_error("Evasion failed: #{e.class} #{e}")
      elog("Evasion failed: #{e.class} #{e}", 'core', LEV_0)
      dlog("Call stack:\n#{$@.join("\n")}", 'core', LEV_3)
      evasion_module.cleanup
      return
    end
  end

  def self.job_cleanup_proc(ctx)
    evasion_module = ctx[0]
    evasion_module.framework.events.on_module_complete(evasion_module)
    # Allow the exploit to cleanup after itself, that messy bugger.
    evasion_module.cleanup
  end

end

end
end
