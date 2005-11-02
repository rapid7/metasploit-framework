require 'thread'
require 'msf/core/recon'

module Msf

###
#
# The states that a host can be in.
#
###
module HostState
	#
	# The host is alive.
	#
	Alive   = "alive"
	#
	# The host is dead.
	#
	Dead    = "down"
	#
	# The host state is unknown.
	#
	Unknown = "unknown"
end

###
#
# The states that a service can be in.
#
###
module ServiceState
	#
	# The service is alive.
	#
	Up      = "up"
	#
	# The service is dead.
	#
	Dead    = "down"
	#
	# The service state is unknown.
	#
	Unknown = "unknown"
end


###
# 
# This class manages the tracking of entities and the dispatching of events
# pertaining to recon information collection.  When hosts are discovered, the
# recon module tracks them and dispatches the appropriate events to the
# framework event manager so that subscribers can be notified.
#
###
class ReconManager

	include Framework::Offspring

	###
	#
	# This mixin is used to extend Host entity instances such that the recon
	# manager can track internal state information.
	#
	###
	module ExtendedHostState
		#
		# Tracks the number of manager state unknowns returned.
		#
		attr_accessor :_mgr_state_unknown
	end

	def initialize(framework)
		self.framework       = framework;
		self.host_hash       = Hash.new
		self.host_hash_mutex = Mutex.new
	end

	##
	#
	# Host reporting
	#
	##

	#
	# Reports a host as being in a given state by address.
	#
	def report_host_state(mod, address, state, context = nil)
		# TODO: use the current thread's Comm as part of the hash key to support
		# conflicting addresses in different networks (established through
		# different comms).
		hash_key = host_hash_key(address)

		# If a host already exists with this information, then check to see what
		# status we received.
		if (host = host_hash[hash_key])
			if (state == HostState::Unknown)
				host._mgr_state_unknown += 1
			elsif (state == HostState::Dead)
				dead_host(host, context)
			else
				host._mgr_state_unknown = 0
			end
		# Otherwise, if we have no host yet, get one and start handling it.
		elsif (state == HostState::Alive)
			host = Recon::Entity::Host.new(address)

			new_host(hash_key, host, context)
		end

		# TODO: evalulate _mgr_state_unknown to determine if the host should be
		# dead
	end

	#
	# This method reports a host's service state.
	#
	def report_service_state(mod, host, proto, port, state, context = nil)

		# If the supplied host object has not yet been registered, do so now.
		# This occurs when a service module happens to discover a host that was
		# not originally thought to have existed
		if (host.needs_register != false and 
		    state == ServiceState::Up)
			new_host(host_hash_key(host.address), host, context)
		end

		# Define the service entity name
		ename = "port_#{port}"

		# Get the proto subcontainer for this entity, or add it if it isn't
		# already defined.
		p = host.services.add_entity_subcontainer(proto.downcase)

		# Now that we have the protocol subcontainer, get the service instance
		# associated witht he port (if one has been defined).
		if (service = p.get_entity(ename))
			# TODO: update
		elsif (state == ServiceState::Up)
			service = Recon::Entity::Service.new(proto, port)

			p.add_entity("port_#{ename}", service)

			# TODO: Notify
		end
	end

	#
	# This method returns the host object associated with the supplied address.
	# If one does not exist, it is created.
	#
	def get_host(address)
		host_hash[host_hash_key(address)]
	end

protected

	#
	# This method returns the hash key to use with the supplied address. 
	#
	# TODO: make this use comm info
	#
	def host_hash_key(address)
		address
	end

	#
	# Called when a new host is detected.
	#
	def new_host(hash_key, host, context)
		# Extend the host and initialize it properly
		host.extend(ExtendedHostState)

		host._mgr_state_unknown = 0

		# Add the host tot he host hash
		host_hash_mutex.synchronize {
			self.host_hash[hash_key] = host
		}

		ilog("recon: New host discoverered: #{host.pretty}", "core",
			LEV_1)

		# Now that the host has registered, we can't flag it up.
		host.needs_register = false

		# Notify any host event subscribes of our new found fate.
		framework.events.on_host_changed(
			context, host, ReconEvent::EntityChangeType::Add)
	end

	#
	# Processes cleanup necessary when a dead host is encountered.
	#
	def dead_host(host, context)
		host_hash_mutex.synchronize {
			self.host_hash.delete(host)
		}

		# Notify any host event subscribers that the host has died.
		framework.events.on_host_changed(
			context, host, ReconEvent::EntityChangeType::Remove)
	end

	attr_accessor :host_hash
	attr_accessor :host_hash_mutex

end

end
