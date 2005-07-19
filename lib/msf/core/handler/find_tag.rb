require 'msf/core/handler/find_port'

module Msf
module Handler

###
#
# FindTag
# -------
#
# This handlers implements tag-based findsock handling.
#
###
module FindTag

	include FindPort

	def self.handler_type
		return "find_tag"
	end

	def initialize(info = {})
		super

		register_advanced_options(
			[
				OptString.new('TAG', [ true, "The four byte tag to signify the connection.", "msf!" ])
			], Msf::Handler::FindTag)
	end

protected

	#
	# Prefix the stage with this...
	#
	def _find_prefix(sock)
		self.stage_prefix = _find_tag
	end

	#
	# Returns the tag we'll be using.
	#
	def _find_tag
		tag  = (datastore['TAG'] || "msf!")
		tag += ("\x01" * (tag.length - 4))

		return tag[0, 4]
	end

end

end
end
