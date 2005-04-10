#!/usr/bin/ruby

module Rex
module Post
module Meterpreter

class Extension

	def initialize(client, name)
		self.client = client
		self.name   = name
	end

	attr_accessor :name
	protected
	attr_accessor :client
end

end; end; end
