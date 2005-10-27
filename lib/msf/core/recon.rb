module Msf

###
#
# ReconEvents
# -----------
#
# This interface is called by recon modules to notify the framework when 
# network elements, services, or other types of things recon modules
# might discovery.
#
###
module ReconEvents

	module EntityChangeType
		Add    = 1
		Update = 2
		Remove = 3
	end

	# TODO: try to do some re-use on these shared entity dispatch routines so
	# prevent code duplication

	##
	#
	# Host entity event notifications
	#
	##

	#
	# This routine is called when a change is made to a host, such as it being
	# added, modified, or removed.
	#
	def on_host_changed(context, host, change_type)
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
	# This routine is called whenever a new host is found.
	#
	def on_new_host(context, host)
	end

	#
	# This routine is called whenever a change is made to an existing
	# host.
	#
	def on_updated_host(context, host)
	end

	#
	# Called when a host is considered to be dead after having
	# previously been valid.
	#
	def on_dead_host(context, host)
	end

	#
	# This routine is called whenever a host attribute is found.
	#
	def on_new_host_attribute(context, host, attribute)
	end

	##
	#
	# Service entity event notifications
	#
	##

	#
	# This routine is called when a change is made to a service, such as it being
	# added, modified, or removed.
	#
	def on_service_changed(context, host, service, change_type)
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
	# This routine is called whenever a new service is found.
	#
	def on_new_service(context, host, service)
	end

	#
	# This routine is called whenever a change is made to an existing
	# service.
	#
	def on_updated_service(context, host, service)
	end

	#
	# Called when a service is considered to be dead after having
	# previously been valid.
	#
	def on_dead_service(context, host, service)
	end

	#
	# This routine is called whenever a service attribute is found.
	#
	def on_new_service_attribute(context, host, service, attribute)
	end

end

end
