module Msf
module Simple

###
#
# This class provides an interface to various statistics about the
# framework instance.
#
###
class Statistics
	include Msf::Framework::Offspring

	#
	# Initializes the framework statistics.
	#
	def initialize(framework)
		self.framework = framework
	end

	#
	# Returns the number of encoders in the framework.
	#
	def num_encoders
		framework.modules.using_cache ?
			framework.modules.cached_counts[MODULE_ENCODER] :
			framework.encoders.length
	end

	#
	# Returns the number of exploits in the framework.
	#
	def num_exploits
		framework.modules.using_cache ?
			framework.modules.cached_counts[MODULE_EXPLOIT] :
			framework.exploits.length
	end

	#
	# Returns the number of NOP generators in the framework.
	#
	def num_nops
		framework.modules.using_cache ?
			framework.modules.cached_counts[MODULE_NOP] :
			framework.nops.length
	end

	#
	# Returns the number of payloads in the framework.
	#
	def num_payloads
		framework.modules.using_cache ?
			framework.modules.cached_counts[MODULE_PAYLOAD] :
			framework.payloads.length
	end

	#
	# Returns the number of auxiliary modules in the framework.
	#
	def num_auxiliary
		framework.modules.using_cache ?
			framework.modules.cached_counts[MODULE_AUX] :
			framework.auxiliary.length
	end

	#
	# Returns the number of stages in the framework.
	#
	def num_payload_stages
		framework.payloads.stages.length
	end

	#
	# Returns the number of stagers in the framework.
	#
	def num_payload_stagers
		framework.payloads.stagers.length
	end

	#
	# Returns the number of singles in the framework.
	#
	def num_payload_singles
		framework.payloads.singles.length
	end
end

end
end