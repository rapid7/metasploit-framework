#!/usr/bin/ruby

# Rex::Struct2
module Rex
module Struct2

class Generic
	
	require 'Rex/Struct2/Element'
	include Rex::Struct2::Element

	attr_reader  :default
	attr_writer  :default

	def initialize(packspec, default=nil)
		@packspec = packspec
		@default  = default
		reset()
	end

	def reset
		self.value = @default
	end

	def to_s
		# I realize this will bomb out if this isn't an integer, for
		# example if it is nil.  That should only happen for a user
		# error so that's what I want it to do...
		string = [ @value ].pack(@packspec)
		if restraint && restraint.max
			return string.slice(0, restraint.max)
		else
			return string
		end
		# what to do for restraint.min?!?
	end

	def from_s(bytes)
		value = bytes.unpack(@packspec)[0]
		# return nil on unpack error
		return if !value
		len = slength()
		# error on any restraint issues
		return if restraint && restraint.max && len > restraint.max
		return if restraint && restraint.min && len < restraint.min
		# else set our value and return length used for this element
		self.value = value
		return(len)
	end

end

# end Rex::Struct2
end
end
