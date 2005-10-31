module Msf
class Recon
class Entity

require 'msf/core/recon/entity/group'

###
#
# Host
# ----
#
# This class represents a logical host entity.  Hosts symbolize a machine that
# may have zero or more services running on it.  Information about the host,
# such as platform, architecture, and other attributes may be gathered and
# populated over time after its initialize discovery through a host discoverer
# recon module.
#
###
class Host < Entity

	###
	#
	# SystemAttributeGroup
	# --------------------
	#
	# This class defines some of the standard system attributes that a host
	# would have.
	#
	###
	class SystemAttributeGroup < Attribute::Group

		#
		# The platform that the host is running.
		#
		def_attr :platform
		#
		# The architecture that the host is running.
		#
		def_attr :arch
		#
		# The time on the host machine.
		#
		def_attr :time

	end

	def initialize(address)
		super()

		# Holds the address of the host that this entity instance is associated
		# with.
		self.address = address

		# Add an attribute group that will contain system information for this
		# host.
		self.sys = SystemAttributeGroup.new

		# Create a service group instance for this host.
		self.services = ServiceGroup.new
	end

	# 
	# This method returns a pretty string representing this host.
	#
	def pretty
		"#{address}"
	end

	#
	# The address that the host instance is associated with.
	#
	attr_reader :address
	#
	# The system attributes for this host.
	#
	attr_reader :sys
	#
	# The services known to be running on this host.
	#
	attr_reader :services

protected

	attr_writer :address, :sys, :services # :nodoc:

end

end
end
end
