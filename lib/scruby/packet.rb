#!/usr/bin/env ruby
# Copyright (C) 2007 Sylvain SARMEJEANNE

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2.

# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 

module Scruby
class Packet

	attr_accessor :layers_list

	# Constructor
	def initialize(arg1, arg2)

		# List of layers
		@layers_list = []

		# There are two cases for the arguments:
		# 1) arg1 is a string to dissect and arg2 the wanted dissector
		# 2) arg1 and arg2 are layers to bind together.

		# First case
		if arg1.is_a?(String) and arg2.is_a?(String)

			# Getting the dissector from its string
			dis = Scruby.get_dissector(arg2)
			return if not dis

			# These variables are used in the loop below.
			remain = arg1

			begin
				# Creating a new layer and adding it to the current packet
				new_layer = dis.new(remain)
				@layers_list.push(new_layer)

				# Preparing the remaining string for the next loop
				remain = new_layer.tobedecoded

				# If the upper layer was guessed by the new layer
				if not new_layer.guesses[0].nil?
					# In this version, only the first guess is considered.
					dis = new_layer.guesses[0]

				# Else, it is considered as raw data.
				else
					dis = Raw
				end

			end until remain.length == 0

		# Second case
		else
			@layers_list = [arg1, arg2].flatten
		end
	end

	def /(upper)
		return Packet./(self, upper)
	end

	# Add a layer/packet/some raw data on top of a layer/packet/some raw data
	def Packet./(lower, upper)

		# Transforms a string into a Raw layer. This allows
		# "IP()/"GET HTTP 1.0\r\n\r\n".
		lower = Raw.new(:load=>lower) if lower.is_a?(String)
		upper = Raw.new(:load=>upper) if upper.is_a?(String)

		# Packet/Layer
		if lower.instance_of?(Packet) and not upper.instance_of?(Packet)
			return Packet.new(lower.layers_list, upper)

		# Packet/Packet
		elsif lower.instance_of?(Packet) and upper.instance_of?(Packet)
			return Packet.new(lower.layers_list, upper.layers_list)

		# Layer/Packet
		elsif not lower.instance_of?(Packet) and upper.instance_of?(Packet)
			return Packet.new(lower, upper.layers_list)

		# Layer/Layer
		elsif not lower.instance_of?(Packet) and not upper.instance_of?(Packet)
			return Packet.new(lower, upper)
		end

	end

	# Converts an object to a string
	def to_s

		out = ''

		@layers_list.each do |layer|
			out += layer.to_s
		end

		return out
	end

	# Displays the packet with more details than tostring
	def show

		out = ''

		@layers_list.each do |layer|
			out += layer.show + "\n"
		end

		return out

	end

	# Returns the string ready to be sent on the wire
	def to_net
		out = ''
		payload = ''
		underlayer = nil

		@layers_list.each do |layer|
			# Only some protocols need to be aware of upper layers
			if Scruby.aware_proto.include?(layer.protocol)
			payload = self.get_payload(layer)
			end

			layer.pre_send(underlayer, payload)
			out += layer.to_net()

			underlayer = layer
			payload = ''
		end

		return out
	end

	# Returns the payload of a layer
	def get_payload(layer_arg = self)

		payload = ''
		concat = false

		@layers_list.each do |layer|
			if layer == layer_arg
			concat = true
			elsif concat == true
			payload += layer.to_net()
			end

		end

		return payload
	end

	# Return the first layer of this type with its payload
	def get_layer(wanted_layer)

		mylayer = nil

		# Get the index of the first occurance of this layer
		@layers_list.each do |layer|

			if layer.class == wanted_layer
				mylayer = layer
			end
		end

		# No occurance was found
		return if mylayer.nil?

		# Getting the index of the wanted layer
		index = @layers_list.index(mylayer)

		# Returning a packet contains all layers, beginning at the wanted layer
		return Packet.new(@layers_list[index..-1], nil)
	end

	# Return the first layer of this type with its payload
	# Differs from get_layer() in that it returns the layer not the packet object
	def layer(wanted_layer)
		ret = get_layer(wanted_layer)
		ret.layers_list[0]
	end
	
	# Checks wether the packet has a given layer
	def has_layer(wanted_layer)
		return (not self.get_layer(wanted_layer).nil?)
	end

	# Returns the last layer of the packet
	def last_layer
		return @layers_list[-1]
	end

	# Decode the raw data with the given dissector
	def decode_payload_as(dissector)
		last = self.last_layer

		# Applying this function doesn't make sense if Raw isn't the last layer
		return if last.class.to_s.split('::')[1] != 'Raw'

		# Building a new packet from the Raw payload with the given dissector
		p = Packet.new(last.load, dissector.to_s.split('::')[1])

		# Removing the Raw layer from the original packet
		@layers_list.pop

		# Binding the new packet over the original packet
		@layers_list.concat(p.layers_list)
	end

end
end