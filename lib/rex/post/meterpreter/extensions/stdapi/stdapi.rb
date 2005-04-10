#!/usr/bin/ruby

require 'Rex/Post/Meterpreter/Extension'
require 'Rex/Post/Meterpreter/Extensions/Stdapi/Process'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi

# Constants
TLV_TYPE_PID = TLV_META_TYPE_UINT | 0

###
#
# Stdapi
# ------
#
# Standard ruby interface to remote entities
#
###
class Stdapi < Extension
	def initialize(client)
		super(client, 'stdapi')
	end

	def brand(klass)
		klass = klass.dup
		klass.client = self.client
		return klass
	end

	def process
		brand(Rex::Post::Meterpreter::Extensions::Stdapi::Process)
	end
end

end; end; end; end; end
