#!/usr/bin/ruby

module Rex
module Post
module Meterpreter

###
#
# ObjectAliases
# -------------
#
# Generic object aliases from a class instance referenced symbol to an 
# associated object of an arbitrary type
#
###
class ObjectAliases

	def initialize()
		self.aliases = {}
	end

	# Pass-thru aliases
	def method_missing(symbol, *args)
		return self.aliases[symbol.to_s];
	end

	attr_accessor :aliases
end

end; end; end
