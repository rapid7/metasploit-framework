module Msf
module Recon
class Discoverer

###
#
# Host
# ----
#
# This class provides a base class for all recon modules that attempt to
# discover the presence of a host.
#
###
class Host < Msf::Recon::Discoverer

	def discoverer_type
		Type::Host
	end

	# TODO: methods to start a probe operation, default implementations for
	# calling handlers

end

###
#
# HostAttribute
# -------------
#
# This class provides a base class for all recon modules that attempt to
# discover specific attributes about a host that was detected through a Host
# discoverer recon module.
#
###
class HostAttribute < Msf::Recon::Discoverer
	def discoverer_type
		Type::HostAttribute
	end
end

end
end
end
end
