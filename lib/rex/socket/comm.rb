require 'rex/socket'

module Rex
module Socket

###
#
# Comm
# ----
#
# This mixin provides the basic interface that a derived class must implement
# in order to be a compatible comm class.
#
###
module Comm

	#
	# Creates a compatible socket based on the supplied uniform parameters.
	#
	def self.create(param)
		raise NotImplementedError
	end

end

end
end

