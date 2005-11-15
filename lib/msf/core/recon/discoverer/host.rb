require 'thread'
require 'rex/socket/subnet_walker'

module Msf
class Recon
class Discoverer

###
#
# This class provides a base class for all recon modules that attempt to
# discover the presence of a host.
#
###
class Host < Msf::Recon::Discoverer

	#
	# Initializes an instance of a host discoverer recon module and adds
	# options that are common to all host discoverers, like subnet and netmask.
	#
	def initialize(info = {})
		super

		# Initialize the mutex that we'll use to synchronize the subnet walker
		# instance that's created during discovery
		self.swalker_mutex = Mutex.new

		# TODO - support random scan
		#register_advanced_options(
		#	[
		#		OptBool.new('RandomScan', [ 0, 'Scan the subnet in a random order', 'false' ])
		#	], Msf::Recon::Discoverer::Host)

		# Register the options that this particular discovery module uses
		register_options(
			[
				OptAddress.new('SUBNET',  [ 1, 'The subnet to scan'        ]),
				OptAddress.new('NETMASK', [ 1, 'The netmask of the subnet' ])
			], Msf::Recon::Discoverer::Host)
	end

	#
	# This method returns that this is a host discoverer recon module.
	#
	def discoverer_type
		Type::Host
	end

	#
	# This method is called when a host should be probed to determine whether
	# or not it is alive.  If the host is found to be alive, HostState::Alive
	# should be returned.  Otherwise, if a host was found to be dead, then
	# HostState::Dead should be returned.  If its state could not be
	# determined, HostState::Unknown should be returned.
	#
	# This method can also return a hash that contains information that will be
	# passed as part of the event context to the reporting subsystem of the
	# recon manager.  This EventContext instance will, in turn, be passed to
	# any subscribers of recon-related events.  For instance, if a port scanner
	# connects to a port on a given host, it can pass the connection around to
	# other recon modules to give them a chance to work with it.  The following
	# keys are special in a hash returned from probe_host:
	#
	#   state      - Equivalent to one of the three HostState values.
	#   connection - The connection associated with the host (TCP, UDP, etc).
	#
	def probe_host(address)
		HostState::Unknown
	end

	#
	# This method acts the same as the probe_host method except it takes as an
	# argument an array of IP addresses to probe and expects an array of
	# address statuses to be returned to that corresponds to the array of
	# addresses passed in as arguments.  This method is only called if
	# hosts_per_block is not one.
	#
	# The array elements can also take the form of a hash as described in the
	# probe_host method description.
	#
	def probe_host_block(addresses)
		addresses.map { HostState::Unknown }
	end

	#
	# Allows a derived class to cleanup anything, like a socket, that may have
	# been used during the probe operation.  The state parameter is equivalent
	# to the return value from probe_host (or probe_host_block for each entry
	# in the array).
	#
	def probe_host_cleanup(address, state)
	end

protected

	#
	# This method initializes the subnet walker for this instance and gets the
	# ball rolling.
	#
	def discovery_startup
		# Create the subnet walker instance
		self.swalker = Rex::Socket::SubnetWalker.new(
			datastore['SUBNET'], datastore['NETMASK'])
	end

	#
	# This is the entry point for any number of threads that may be spawned to
	# discover hosts for this module.
	#
	def discovery_thread
		# If we're processing one IP address per block, then do a singular probe
		# by calling probe_host for each address.
		if (hosts_per_block == 1)
			while (ip = next_ip)
				report_host_state(ip, probe_host(ip))
			end
		# Otherwise, get up to the number of hosts per block defined and call
		# probe_host_block.
		else
			begin
				addresses = []

				# Fill up the array of addresses as high as we can go
				while (ip = next_ip)
					addresses << ip
				end

				# If we have no addresses to process, then break out of the loop
				break if (addresses.length == 0)

				# Probe the host block and get the statuses
				statuses = probe_host_block(addresses)

				# If no statuses were returned, something odd happened, break out.
				if (statuses.length == 0)
					wlog("#{self.refname}: probe of #{addresses.length} addresses returned no status")
					break
				end

				# Report the status associated with each address
				addresses.each_with_index { |address, idx|
					report_host_state(address, statuses[idx])
				}

			end while (true)
		end
	end

	#
	# Returns the next IP address to the caller in a synchronized fashion.  If
	# no IPs are left to be enumerated, nil is returned.
	#
	def next_ip
		swalker_mutex.synchronize {
			swalker.next_ip
		}
	end

	#
	# This method reports host state information to the recon manager, possibly
	# including an event context.
	#
	def report_host_state(ip, istate)
		# Create a nil context
		context = nil
		state   = istate

		# If a hash was returned, we should create an event context to
		# pass to the notification.
		if (istate.kind_of?(Hash))
			context = Msf::Recon::EventContext.new

			# Serialize the context from the hash
			context.from_hash(state)

			# Grab the real state from the hash
			state = istate['state']
		end

		# Report the host's state to the recon manager.
		framework.reconmgr.report_host_state(
			self, ip, state, context)

		# Perform cleanup as necessary (only if istate was a Hash)
		if (context)
			probe_host_cleanup(ip, istate)
		end
	end

	##
	#
	# Defaults that can be overridden by derived classes
	#
	##

	#
	# The default number of hosts to process per-block.  If this number is one,
	# the probe_host method will be called.  Otherwise, the probe_block method
	# will be called which takes an array of IP addresses to probe.
	#
	def hosts_per_block
		1
	end

	attr_accessor :swalker # :nodoc:
	attr_accessor :swalker_mutex # :nodoc:

end

###
#
# HostAttribute
# -------------
#
# This class provides a base class for all recon modules that attempt to
# discover specific attributes about a host that was detected through a Host
# discoverer recon module.
#
###
class HostAttribute < Msf::Recon::Discoverer

	#
	# Returns Type::HostAttribute.
	#
	def discoverer_type
		Type::HostAttribute
	end
end

end
end
end
