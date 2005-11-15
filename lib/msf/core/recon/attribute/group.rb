module Msf
class Recon
module Attribute

require 'msf/core/recon/attribute/container'

###
#
# This class acts as a symbolic attribute group and is simply used as a
# means of containing attributes without being an actual attribute or
# an entity itself.
#
###
class Group
	include Container

	#
	# This routine defines an attribute by name by creating accessors that
	# reference the internal hash.
	#
	def self.def_attr(*args)
		args.each { |name|
			class_eval("
				def #{name}
					attribute_hash['#{name}']
				end
				def #{name}=(val)
					attribute_hash['#{name}'] = val
				end")
		}
	end

	#
	# Initializes the attribute group which is simply a container of
	# attributes.
	#
	def initialize
		initialize_attributes
	end
end

end
end
end
