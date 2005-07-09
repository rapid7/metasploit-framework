require 'Msf/Core'

###
#
# Stager
# ------
#
# Base mixin interface for use by stagers.
#
###
module Msf::Payload::Stager

	def payload_type
		return Msf::Payload::Type::Stager
	end

	# Return the stager payload's raw payload
	def payload
		return module_info['StagerPayload']['Payload']	
	end

	# Return the stager payload's offsets
	def offsets
		return module_info['StagerPayload']['Offsets']
	end

	# Returns the raw stage payload
	def stage_payload
		return module_info['StagePayload']['Payload']
	end

	# Returns variable offsets within the stage payload
	def stage_offsets
		return module_info['StagePayload']['Offsets']
	end

	# Aliases
	alias stager_payload payload
	alias stager_offsets offsets

end
