module Msf
class Recon
module Attribute

###
#
# This mixin provides methods for setting and getting the values
# of various attributes.  As attributes are defined, aliases methods are added
# to the container to make it easier to access the attributes for reading.
# This is done to encourage the direct referencing of attributes for reading
# by an accessor method rather than through using get_attribute which will
# simply return nil if no match was found.  By doing it this way, recon
# modules can try to access the attributes of a host, service, or other entity
# that may not yet be defined and thus lead to an exception being thrown.
# This will indicate that not enough information has been gathered yet for the
# recon module to proceed.
#
###
module Container

	#
	# Initializes the attribute hash.
	#
	def initialize_attributes
		self._attr_hash = Hash.new
	end

	#
	# Wraps get_attribute.
	#
	def [](key)
		get_attribute(key)
	end

	#
	# Wraps set_attribute.
	#
	def []=(key, val)
		set_attribute(key, val)
	end

	#
	# Sets the value of an attribute with the supplied name.
	#
	def set_attribute(name, val)

		# If we've yet to define this method on the container, do so now.
		#
		# TODO: evalulate the performance of doing it this way.
		if (respond_to?(name) == false)
			begin
				instance_eval("
					def #{name}
						_attr_hash['#{name}']
					end")
			rescue SyntaxError
			end
		end

		_attr_hash[name] = val
	end

	#
	# Unsets an attribute entirely.
	#
	def unset_attribute
		_attr_hash.delete(name)
	end

	#
	# Returns the value associated with the supplied attribute name.
	#
	def get_attribute(name)
		_attr_hash[name]
	end

	#
	# Returns a list of all attributes that have had a value set.
	#
	def attributes
		_attr_hash.keys
	end

	#
	# Returns the attribute hash in case direct interaction is necessary.
	#
	def attribute_hash
		_attr_hash
	end

	#
	# Serializes from a hash.
	#
	def from_hash(hsh)
		hsh.each_pair { |k,v|
			set_attribute(k, v)
		}
	end

protected

	attr_accessor :_attr_hash

end

end
end
end
