module Msf
class Recon
class Entity

###
#
# Service
# -------
#
# This class represents a logical service entity.  Services symbolize remote
# functionality provided by a host by means of some network-based protocol,
# such as TCP over IP.  Information about a service, such as its protocol,
# port, banner, and other information is conveyed through attributes of the
# service entity.
#
###
class Service < Entity

	def initialize(proto, port = nil)
		super()

		#
		# Initialize the local attributes
		#
		self.proto = proto
		self.port  = port
	end

	#
	# This method returns a pretty string representation of the service. 
	#
	def pretty
		"#{port} (#{proto})"
	end

	#
	# The protocol this service is using, such as 'tcp'.
	#
	attr_reader :proto
	#
	# The port this service is listening on, if applicable.
	#
	attr_reader :port

protected
	
	attr_writer :proto, :port # :nodoc:

end

end
end
end
