module Msf

###
#
# ReconEvents
# -----------
#
# This interface is called by recon modules to notify the framework when 
# network elements, services, or other types of things recon modules
# might discovery.
#
###
module ReconEvents

	def on_recon_discovery(group, info)
		return nil
	end

end

end
