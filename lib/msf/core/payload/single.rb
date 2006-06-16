require 'msf/core'

###
#
# Base mixin interface for use by single payloads.  Single 
# payloads are differentiated from stagers and stages by the
# fact that they run as part of the first stage and have
# no subsequent stages.
#
###
module Msf::Payload::Single

	#
	# Sets the payload type to that of a single payload.
	#
	def payload_type
		return Msf::Payload::Type::Single
	end

end
