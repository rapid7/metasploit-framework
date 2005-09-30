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

	#
	# Indicates whether or not this comm can be chained with other chainable
	# comms.  This is particularly important for things like Proxy Comms that
	# can be proxied through one another.  The semantics of this are currently
	# undefined and will probably need some more thought.
	#
	def chainable?
		false
	end

end

end
end

