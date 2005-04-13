#!/usr/bin/ruby

require 'Rex/Post/Meterpreter/Channels/Pool'

module Rex
module Post
module Meterpreter
module Channels
module Pools

###
#
# File
# ----
#
# This class represents a channel that is associated with a file
# on the remote half of the meterpreter connection.
#
###
class File < Rex::Post::Meterpreter::Channels::Pool

	##
	#
	# Constructor
	#
	##

	# Initializes the file channel instance
	def initialize(client, cid, type, flags)
		super(client, cid, type, flags)
	end

end

end; end; end; end; end
