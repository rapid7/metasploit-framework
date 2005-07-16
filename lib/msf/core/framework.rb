require 'msf/core'

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

	#
	# Versioning information
	#
	Major    = 3
	Minor    = 0
	Version  = "#{Major}.#{Minor}"
	Revision = "$Revision$"
	
	#
	# Mixin meant to be included into all classes that can have instances that
	# should be tied to the framework, such as modules.
	#
	module Offspring
		attr_accessor :framework	
	end

	require 'msf/core/module_manager'
	require 'msf/core/session_manager'

	def initialize()
		self.events    = EventDispatcher.new
		self.modules   = ModuleManager.new(self)
		self.sessions  = SessionManager.new(self)
		self.datastore = DataStore.new
	end

	#
	# Returns the module set for encoders
	#
	def encoders
		return modules.encoders
	end

	#
	# Returns the module set for exploits
	#
	def exploits
		return modules.exploits
	end

	#
	# Returns the module set for nops
	#
	def nops
		return modules.nops
	end

	#
	# Returns the module set for payloads
	#
	def payloads
		return modules.payloads
	end

	#
	# Returns the module set for recon modules
	#
	def recon
		return modules.recon
	end

	attr_reader   :events
	attr_reader   :modules
	attr_reader   :sessions
	attr_reader   :datastore

protected

	attr_writer   :events
	attr_writer   :modules
	attr_writer   :sessions
	attr_writer   :datastore

end

end
