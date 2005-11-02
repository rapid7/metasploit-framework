module Msf
class Recon
class Entity

class Group
end

###
#
# This mixin is included when something wishes to be capable of containing
# entities of an arbitrary type.
#
###
module Container

	#
	# Initializes the array of entities.
	#
	def initialize_entities
		self._entity_hash = Hash.new
	end

	#
	# This routine adds a sub-container of entities to this entity container.
	#
	def add_entity_subcontainer(name, container = Group.new)
		add_entity(name, container)
	end

	#
	# Adds an entity to the container.
	#
	def <<(entity)
		add_entity(entity)
	end

	#
	# Adds an entity to the container.
	#
	def add_entity(name, entity)
		self._entity_hash[name] = entity

		if (respond_to?(name) == false)
			instance_eval("
				def #{name}
					_entity_hash[#{name}]
				end
				")
		end

		entity
	end

	#
	# Returns the entity associated with the supplied name.
	#
	def get_entity(name)
		_entity_hash[name]
	end

	#
	# Removes an entity from the hash of entities.
	#
	def delete_entity(entity)
		self._entity_hash.delete(entity)
	end

	#
	# Returns the hash of entities to the caller.
	#
	def entities
		_entity_hash
	end

protected

	#
	# The protected entity hash itself.
	#
	attr_accessor :_entity_hash

end

end
end
end
