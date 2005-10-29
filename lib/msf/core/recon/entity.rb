module Msf
class Recon

###
#
# Entity
# ------
#
# This class represents an abstract entity that can be discovered during the 
# recon process, such as a host, a service, a user, or some other formal
# and distinct thing.  All entities can have zero or may attributes and
# may contain zero or more entities of various types.  This is pretty
# abstract, like woah.
#
###
class Entity

	require 'msf/core/recon/attribute/group'
	require 'msf/core/recon/entity/group'

	#
	# Entities are all offspring of the framework
	#
	include Framework::Offspring
	#
	# All entities can contain attributes
	#
	include Attribute::Container
	#
	# All entities can contain zero or more entities
	#
	include Entity::Container

	require 'msf/core/recon/entity/host'
	require 'msf/core/recon/entity/service'
	require 'msf/core/recon/entity/user'

	#
	# Initializes the entity's attributes and sub-entities.
	#
	def initialize
		initialize_attributes
		initialize_entities
	end

	#
	# Returns the entity's type.
	#
	def entity_type
		'unknown'
	end

end

end
end
