module Msf
class Recon
class Entity

require 'msf/core/recon/entity/container'

###
#
# This class acts as a symbolic entity group and is simply used to group
# entities together without itself being an entity.  This is analagous to the
# Attribute::Group class.
#
###
class Group

	include Container

	#
	# Initializes an entity group which is simply an entity container.
	#
	def initialize
		initialize_entities
	end

end

###
#
# This class extends the Group base class to provide some default protocol
# group sub-containers for entities that are specific to a given service
# protocol.
#
###
class ServiceGroup < Group

	#
	# Initializes a group of services and breaks them down into their
	# sub-protocols which can be accessed through the 'tcp' and 'udp'
	# attributes.
	#
	def initialize
		super

		# Add protocol-specific subcontainer groups
		self.tcp = Group.new
		self.udp = Group.new
	end

	#
	# This attribute is a sub-group that contains all TCP services.
	#
	attr_reader :tcp
	#
	# This attribute is a sub-group that contains all UDP services.
	#
	attr_reader :udp

protected

	attr_writer :tcp, :udp # :nodoc:

end

#
# Aliased class names for now.
#
HostGroup = Group
UserGroup = Group

end
end
end
