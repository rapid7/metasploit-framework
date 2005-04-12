#!/usr/bin/ruby

module Rex
module Post
module Meterpreter

###
#
# ChannelContainer
# ----------------
#
# Interface for containing channel objects
#
###
module ChannelContainer

	# Initializes the channel association hash
	def initialize_channels
		self.channels = {}
	end

	# Adds a channel to the container that is indexed by its channel identifier
	def add_channel(channel)
		self.channels[channel.cid] = channel
	end

	# Looks up a channel instance based on its channel identifier
	def find_channel(cid)
		return self.channels[cid]
	end

	# Removes a channel based on its channel identifier
	def remove_channel(cid)
		return self.channels.delete(cid)
	end

protected
	attr_accessor :channels

end

end; end; end
