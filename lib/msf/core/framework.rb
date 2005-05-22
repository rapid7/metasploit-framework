require 'Msf/Core'

module Msf

###
#
# Framework
# ---------
#
# This class is the primary context that modules, scripts, and user
# interfaces interact with.  It ties everything together.
#
###
class Framework

	def initialize()
		self.events   = EventDispatcher.new
		self.modules  = ModuleManager.new
	end

	def encoders
		return modules.encoders
	end

	def nops
		return modules.nops
	end

	def exploits
		return modules.exploits
	end

	def recon
		return modules.recon
	end

	attr_reader   :events
	attr_reader   :modules

protected

	attr_writer   :events
	attr_writer   :modules

end

end
