module Msf
module Simple

###
#
# A simplified recon wrapper.
#
###
module Recon

	include Module

	#
	# Wraps the discovery process in a simple wrapper.
	#
	def self.discover_simple(recon, opts = {})
		# Initialize user interaction
		recon.init_ui(
			opts['LocalInput'],
			opts['LocalOutput'])

		# Start the discovery process
		recon.start_discovery

		# Wait for the discovery to complete
		recon.wait_for_completion

		# Reset the user interface
		recon.reset_ui
	end

	#
	# Calls the class method.
	#
	def discover_simple(opts = {})
		Msf::Simple::Recon.discover_simple(self, opts)	
	end

end

end
end
