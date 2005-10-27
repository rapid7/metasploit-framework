module Msf
module Recon

###
#
# Discoverer
# ----------
#
# This class acts as a base class for all recon modules that attempt to
# discover new entities and attributes of entities.  For instance, recon
# modules that attempt to discover the presence of a host, service, user, or
# other forms of entities are considered sub-classes of discoverer recon
# modules.  On top of that, recon modules that attempt to discover the
# attributes of any of the previously described entities are considered
# discoverer recon modules as well.
#
###
class Discoverer < Msf::Recon

	#
	# The types of discoverer recon modules that are known about by default.
	#
	module Type
		
		#
		# Unknown discoverer module type.
		#
		Unknown = 'unknown'

		#
		# Host discoverer.
		#
		Host = 'host'

		#
		# Host attribute discoverer.
		#
		HostAttribute = 'host attribute'

	end

	require 'msf/core/recon/discoverer/host'

	#
	# This method returns the type of discoverer recon module.
	#
	def discoverer_type
		Type::Unknown
	end

end

end
end
