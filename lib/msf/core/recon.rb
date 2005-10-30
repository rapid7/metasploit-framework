require 'msf/core/module'

module Msf

###
#
# ReconEvent
# ----------
#
# This interface is called by recon modules to notify the framework when 
# network elements, services, or other types of things recon modules
# might discovery.
#
###
module ReconEvent

	module EntityChangeType
		Add    = 1
		Update = 2
		Remove = 3
	end

	###
	#
	# HostSubscriber
	# --------------
	#
	# This module provides methods for handling host entity notifications.
	#
	###
	module HostSubscriber

		#
		# This routine is called when a change is made to a host, such as it being
		# added, modified, or removed.
		#
		def self.on_host_changed(context, host, change_type)
			case change_type
				when EntityChangeType::Add
					on_new_host(context, host)
				when EntityChangeType::Update
					on_updated_host(context, host)
				when EntityChangeType::Remove
					on_dead_host(context, host)
			end
		end

		#
		# Calls the class method.
		#
		def on_host_changed(context, host, change_type)
			self.class.on_host_changed(context, host, change_type)
		end

		#
		# This routine is called whenever a new host is found.
		#
		def self.on_new_host(context, host)
		end

		#
		# Calls the class methods.
		#
		def on_new_host(context, host)
			self.class.on_new_host(context, host)
		end

		#
		# This routine is called whenever a change is made to an existing
		# host.
		#
		def self.on_updated_host(context, host)
		end

		#
		# Calls the class method.
		#
		def on_updated_host(context, host)
			self.class.on_updated_host(context, host)
		end

		#
		# Called when a host is considered to be dead after having
		# previously been valid.
		#
		def self.on_dead_host(context, host)
		end

		#
		# Calls the class method.
		#
		def on_dead_host(context, host)
			self.class.on_dead_host(context, host)
		end

		#
		# This routine is called whenever a host attribute is found.
		#
		def self.on_new_host_attribute(context, host, attribute)
		end

		#
		# Calls the class method.
		#
		def on_new_host_attribute(context, host, attribute)
			self.class.on_new_host_attribute(context, host, attribute)
		end

	end

	###
	#
	# ServiceSubscriber
	# -----------------
	#
	# This module provides methods for handling notifications that deal with
	# service entities.
	#
	###
	module ServiceSubscriber

		#
		# This routine is called when a change is made to a service, such as it being
		# added, modified, or removed.
		#
		def self.on_service_changed(context, host, service, change_type)
			case change_type
				when EntityChangeType::Add
					on_new_service(context, host, service)
				when EntityChangeType::Update
					on_updated_service(context, host, service)
				when EntityChangeType::Remove
					on_dead_service(context, host, service)
			end
		end

		#
		# Calls the class method.
		#
		def on_service_changed(context, host, service, change_type)
			self.class.on_service_changed(context, host, service, change_type)
		end

		#
		# This routine is called whenever a new service is found.
		#
		def self.on_new_service(context, host, service)
		end

		#
		# Calls the class method.
		#
		def on_new_service(context, host, service)
			self.class.on_new_service(context, host, service)
		end

		#
		# This routine is called whenever a change is made to an existing
		# service.
		#
		def self.on_updated_service(context, host, service)
		end

		#
		# Calls the class method.
		#
		def on_updated_service(context, host, service)
			self.class.on_updated_service(context, host, service)
		end

		#
		# Called when a service is considered to be dead after having
		# previously been valid.
		#
		def self.on_dead_service(context, host, service)
		end

		#
		# Calls the class method.
		#
		def on_dead_service(context, host, service)
			self.class.on_dead_service(context, host, service)
		end

		#
		# This routine is called whenever a service attribute is found.
		#
		def self.on_new_service_attribute(context, host, service, attribute)
		end
		
		#
		# Calls the class method.
		#
		def on_new_service_attribute(context, host, service)
			self.class.on_new_service_attribute(context, host, service)
		end

	end


	#
	# The ReconEvents base mixin includes all methods from the Host and Service
	# subscriber interfaces.
	#
	include HostSubscriber
	include ServiceSubscriber

end

###
#
# Recon
# -----
#
# The recon class acts as a base class for all recon modules.  It provides a
# common interface for detecting the presence of hosts, services, and the
# attributes of everything in between.  The type of information that can be
# discovered is designed to be generic.
#
###
class Recon < Msf::Module

	#
	# The various basic sub-types of recon modules.
	#
	module Type

		#
		# Indicates that this is an unknown recon module.  This recon module
		# does something other than discover and analyze.
		#
		Unknown = "unknown"

		#
		# Indicates that the recon module discovers things.  Discoverer recon
		# modules are responsible for collecting information about the presence
		# of entities and the attributes of those entities.  For instance,
		# a discoverer module finds hosts and the services running on those
		# hosts and could also determine more granular information about
		# the host and service by determining some of their attributes, such
		# as a host's platform.
		#
		Discoverer = "discoverer"

		#
		# Indicates that the recon module analyzes things.  Analyzer recon
		# modules take information collected by discoverer recon modules and
		# determine or derived more detailed information about an entity or a
		# group of entities.  For instance, an analyzer module may determine
		# that five distinct hosts detected by a discoverer module may actually
		# be on the same machine but just virtual hosted.  Also, analyzer
		# modules might try to do more advanced stuff like crack passwords
		# collected by recon modules and other such fun things.
		#
		Analyzer = "analyzer"
	end

	require 'msf/core/recon/discoverer'
	require 'msf/core/recon/entity'
	require 'msf/core/recon/event_context'

	#
	# Returns MODULE_RECON to indicate that this is a recon module.
	#
	def self.type
		MODULE_RECON
	end

	#
	# Returns MODULE_RECON to indicate that this is a recon module.
	#
	def type
		MODULE_RECON
	end

	#
	# This method returns the general type of recon module.
	#
	def recon_type
		Type::Unknown	
	end

end

end
