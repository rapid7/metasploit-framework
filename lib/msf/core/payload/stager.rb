require 'msf/core'

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
		return module_info['Stager']['Payload']	
	end

	# Return the stager payload's offsets
	def offsets
		return module_info['Stager']['Offsets']
	end

	# Returns the raw stage payload
	def stage_payload
		return module_info['Stage']['Payload']
	end

	# Returns variable offsets within the stage payload
	def stage_offsets
		return module_info['Stage']['Offsets']
	end

	# Aliases
	alias stager_payload payload
	alias stager_offsets offsets

end
