module Msf
class Recon
class Entity

###
#
# Container
# ---------
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
		self._entity_list = Array.new
		self._entity_sub_containers = Hash.new
	end

	#
	# This routine adds a sub-container of entities to this entity container.
	#
	def add_entity_subcontainer(name, container)
		self._entity_sub_containers[name] = container

		instance_eval("
			def #{name}
				_entity_sub_containers['#{name}']	
			end")
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
	def add_entity(entity)
		self._entity_list << entity
	end

	def delete_entity(entity)
		self._entity_list.delete(entity)
	end

	#
	# Returns the list of entities to the caller.
	#
	def entities
		_entity_list
	end

protected

	#
	# The protected entity list itself.
	#
	attr_accessor :_entity_list
	#
	# The hash of entity sub-containers.
	#
	attr_accessor :_entity_sub_containers

end

end
end
end
