require 'msf/core'

module Msf

###
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
	Release  = "-alpha-r2"
	Version  = "#{Major}.#{Minor}#{Release}"
	Revision = "$Revision$"
	
	#
	# Mixin meant to be included into all classes that can have instances that
	# should be tied to the framework, such as modules.
	#
	module Offspring

		#
		# A reference to the framework instance from which this offspring was
		# derived.
		#
		attr_accessor :framework	
	end

	require 'msf/core/module_manager'
	require 'msf/core/session_manager'
	require 'msf/core/recon_manager'

	#
	# Creates an instance of the framework context.
	#
	def initialize()
		self.events    = EventDispatcher.new
		self.modules   = ModuleManager.new(self)
		self.sessions  = SessionManager.new(self)
		self.reconmgr  = ReconManager.new(self)
		self.datastore = DataStore.new
		self.jobs      = Rex::JobContainer.new
		self.plugins   = PluginManager.new(self)
	end

	#
	# Returns the module set for encoders.
	#
	def encoders
		return modules.encoders
	end

	#
	# Returns the module set for exploits.
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

	#
	# Returns the framework version in Major.Minor format.
	#
	def version
		Version	
	end

	#
	# Event management interface for registering event handler subscribers and
	# for interacting with the correlation engine.
	#
	attr_reader   :events
	#
	# Module manager that contains information about all loaded modules,
	# regardless of type.
	#
	attr_reader   :modules
	#
	# Session manager that tracks sessions associated with this framework
	# instance over the course of their lifetime.
	#
	attr_reader   :sessions
	#
	# The global framework datastore that can be used by modules.
	#
	attr_reader   :datastore
	#
	# The framework instance's recon manager.  The recon manager is responsible
	# for collecting and catalogging all recon information that comes in from
	# recon modules.
	#
	attr_reader   :reconmgr
	#
	# Background job management specific to things spawned from this instance
	# of the framework.
	#
	attr_reader   :jobs
	#
	# The framework instance's plugin manager.  The plugin manager is
	# responsible for exposing an interface that allows for the loading and
	# unloading of plugins.
	#
	attr_reader   :plugins

protected

	attr_writer   :events # :nodoc:
	attr_writer   :modules # :nodoc:
	attr_writer   :sessions # :nodoc:
	attr_writer   :datastore # :nodoc:
	attr_writer   :reconmgr # :nodoc:
	attr_writer   :jobs # :nodoc:
	attr_writer   :plugins # :nodoc:

end

end
