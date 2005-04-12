#!/usr/bin/ruby

module Rex
module Post
module Meterpreter

###
#
# Extension
# ---------
#
# Base class for all extensions that holds a reference to the
# client context that they are part of
#
###
class Extension

	# Initializes the client and name attributes
	def initialize(client, name)
		self.client = client
		self.name   = name
	end

	attr_accessor :name
protected
	attr_accessor :client
end

end; end; end
