module Msf
module Simple

###
#
# Statistics
# ----------
#
# This class provides an interface to various statistics about the
# framework instance.
#
###
class Statistics
	include Msf::Framework::Offspring

	def initialize(framework)
		self.framework = framework
	end

	def num_encoders
		self.framework.encoders.length
	end

	def num_exploits
		self.framework.exploits.length
	end
	
	def num_nops
		self.framework.nops.length
	end

	def num_payloads
		self.framework.payloads.length
	end
	
	def num_recon
		self.framework.recon.length
	end
	
	def num_payload_stages
		self.framework.payloads.stages.length
	end
	
	def num_payload_stagers
		self.framework.payloads.stagers.length
	end
	
	def num_payload_singles
		self.framework.payloads.singles.length
	end
end

end
end
