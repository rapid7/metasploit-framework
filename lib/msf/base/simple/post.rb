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
    Msf::Simple::Framework.simplify_module( mod, false )
    yield(mod) if block_given?

    # Import options from the OptionStr or Option hash.
    mod._import_extra_options(opts)

    # Verify the options
    mod.options.validate(mod.datastore)

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
      ctx = [ mod.replicant ]
      mod.job_id = mod.framework.jobs.start_bg_job(
        "Post: #{mod.refname}",
        ctx,
        Proc.new { |ctx_| self.job_run_proc(ctx_) },
        Proc.new { |ctx_| self.job_cleanup_proc(ctx_) }
      )
      # Propagate this back to the caller for console mgmt
      omod.job_id = mod.job_id
    else
      ctx = [ mod ]
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
    begin
      mod.setup
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
        mod.cleanup
        return
      end
    rescue ::Timeout::Error => e
      mod.error = e
      mod.print_error("Post triggered a timeout exception")
      mod.cleanup
      return
    rescue ::Interrupt => e
      mod.error = e
      mod.print_error("Post interrupted by the console user")
      mod.cleanup
      return
    rescue ::Exception => e
      mod.error = e
      mod.print_error("Post failed: #{e.class} #{e}")
      if(e.class.to_s != 'Msf::OptionValidateError')
        mod.print_error("Call stack:")
        e.backtrace.each do |line|
          break if line =~ /lib.msf.base.simple.post.rb/
          mod.print_error("  #{line}")
        end
      end

      elog("Post failed: #{e.class} #{e}", 'core', LEV_0)
      dlog("Call stack:\n#{$@.join("\n")}", 'core', LEV_3)

      mod.cleanup

      return
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

