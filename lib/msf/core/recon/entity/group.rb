module Msf
class Recon
class Entity

require 'msf/core/recon/entity/container'

###
#
# Group
# -----
#
# This class acts as a symbolic entity group and is simply used to group
# entities together without itself being an entity.  This is analagous to the
# Attribute::Group class.
#
###
class Group

	include Container
	
	def initialize
		initialize_entities
	end

end

###
#
# ServiceGroup
# ------------
#
# This class extends the Group base class to provide some default protocol
# group sub-containers for entities that are specific to a given service
# protocol.
#
###
class ServiceGroup < Group

	def initialize
		super

		# Add protocol-specific subcontainer groups
		self.tcp = Group.new
		self.udp = Group.new
	end

	attr_reader :tcp, :udp

protected

	attr_writer :tcp, :udp

end

#
# Aliased class names for now.
#
HostGroup = Group
UserGroup = Group

end
end
end
