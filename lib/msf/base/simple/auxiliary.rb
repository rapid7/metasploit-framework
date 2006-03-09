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
	# Wraps the execution process in a simple wrapper.
	#
	def self.run_simple(mod, opts = {})

		if (not mod.action)
			raise MissingActionError, "You must specify a valid Action", caller
		end

		# Initialize user interaction
		mod.init_ui(
			opts['LocalInput'],
			opts['LocalOutput'])
		
		mod.run()

		# Reset the user interface
		mod.reset_ui
	end

	#
	# Calls the class method.
	#
	def run_simple(opts = {})
		Msf::Simple::Auxiliary.run_simple(self, opts)	
	end

end

end
end
