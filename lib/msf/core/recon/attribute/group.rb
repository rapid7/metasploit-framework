module Msf
module Recon
module Attribute

require 'msf/core/recon/attribute/container'

###
#
# Group
# -----
#
# This class acts as a symbolic attribute group and is simply used as a
# means of containing attributes without being an actual attribute or
# an entity itself.
#
###
class Group
	include Container

	def self.def_attr(name)
		class_eval("
			def #{name}
				attribute_hash['#{name}']
			end
			def #{name}=(val)
				attribute_hash['#{name}'] = val
			end")
	end

	def initialize
		initialize_attributes
	end
end

end
end
end
