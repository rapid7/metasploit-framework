module Msf
module Simple

###
#
# A simplified recon wrapper.
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
	def self.run_simple(mod, opts = {})

		# Import options from the OptionStr or Option hash.
		mod._import_extra_options(opts)
		
		# Verify the ACTION
		if (mod.actions.length > 0 and not mod.action)
			raise MissingActionError, "You must specify a valid Action", caller
		end

		# Verify the options
		mod.options.validate(mod.datastore)

		# Initialize user interaction
		mod.init_ui(opts['LocalInput'],opts['LocalOutput'])

		
		p mod.passive?
		
		if(mod.passive?)		
			mod.framework.jobs.start_bg_job(
				"Auxiliary: #{mod.refname}", 
				mod,
				Proc.new { |mod| self.job_run_proc(mod) },
				Proc.new { |mod| self.job_cleanup_proc(mod) }
			)
		else		
			if (opts['RunAsJob'])
				mod.framework.jobs.start_job(
					"Auxiliary: #{mod.refname}", 
					mod,
					Proc.new { |mod| self.job_run_proc(mod) },
					Proc.new { |mod| self.job_cleanup_proc(mod) }
				)
			else
				self.job_run_proc(mod)
				self.job_cleanup_proc(mod)
			end
		end
	end

	#
	# Calls the class method.
	#
	def run_simple(opts = {})
		Msf::Simple::Auxiliary.run_simple(self, opts)	
	end

protected

	#
	# Job run proc, sets up the module and kicks it off.
	#
	def self.job_run_proc(mod)
		begin
			mod.setup
			mod.run
		rescue ::Exception
			elog("Auxiliary failed: #{$!}", 'core', LEV_0)
			dlog("Call stack:\n#{$@.join("\n")}", 'core', LEV_3)

			mod.cleanup

			raise $!
		end
	end

	#
	# Clean up the module after the job completes.
	#
	def self.job_cleanup_proc(mod)
		# Allow the exploit to cleanup after itself, that messy bugger.
		mod.cleanup
	end

end

end
end
