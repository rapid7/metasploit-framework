#!/usr/bin/ruby

require 'socket'
require 'Rex/Post/Meterpreter/ClientCore'
require 'Rex/Post/Meterpreter/Channel'
require 'Rex/Post/Meterpreter/ChannelContainer'
require 'Rex/Post/Meterpreter/Dependencies'
require 'Rex/Post/Meterpreter/ObjectAliases'
require 'Rex/Post/Meterpreter/Packet'
require 'Rex/Post/Meterpreter/PacketParser'
require 'Rex/Post/Meterpreter/PacketDispatcher'

module Rex
module Post
module Meterpreter

###
#
# Client
# ------
#
# The logical meterpreter client class.  This class manages a single session
# with a meterpreter server instance.
#
###
class Client

	include Rex::Post::Meterpreter::PacketDispatcher
	include Rex::Post::Meterpreter::ChannelContainer

	# Initializes the client context with the supplied socket through
	# which communication with the server will be performed
	def initialize(sock)
		self.sock        = sock
		self.parser      = PacketParser.new
		self.ext         = ObjectAliases.new
		self.ext_aliases = ObjectAliases.new

		register_extension_alias('core', ClientCore.new(self))

		initialize_inbound_handlers
		initialize_channels

		# Register the channel inbound packet handler
		register_inbound_handler(Rex::Post::Meterpreter::Channel)

		monitor_socket
	end

	##
	# 
	# Accessors
	#
	##
	
	# Returns the default timeout that request packets will use when
	# waiting for a response
	def Client.default_timeout
		return 30
	end

	##
	#
	# Alias processor
	#
	##
	
	# Translates unhandled methods into registered extension aliases
	# if a matching extension alias exists for the supplied symbol
	def method_missing(symbol, *args)
		return self.ext_aliases.aliases[symbol.to_s];
	end

	##
	#
	# Extension registration
	#
	##

	# Loads the client half of the supplied extension and initializes it as a
	# registered extension that can be reached through client.ext.[extension].
	def add_extension(name)
		if (Kernel.require("Rex/Post/Meterpreter/Extensions/#{name}/#{name}") == false)
			return false
		end

		ext = eval("Rex::Post::Meterpreter::Extensions::" + name + "::" + name + ".new(self)")

		self.ext.aliases[ext.name] = ext

		return true
	end

	# Deregisters an extension alias of the supplied name
	def deregister_extension(name)
		self.ext.aliases.delete(name)
	end

	# Enumerates all of the loaded extensions
	def each_extension(&block)
		self.ext.aliases.each(block)
	end

	# Registers an aliased extension that can be referenced through
	# client.name
	def register_extension_alias(name, ext)
		self.ext_aliases.aliases[name] = ext
	end

	# Registers zero or more aliases that are provided in an array
	def register_extension_aliases(aliases)
		aliases.each { |a|
			register_extension_alias(a['name'], a['ext'])
		}
	end

	# Deregisters a previously registered extension alias
	def deregister_extension_alias(name)
		self.ext_aliases.aliases.delete(name)
	end

	# Dumps the extension tree
	def dump_extension_tree()
		items = []
		items.concat(self.ext.dump_alias_tree('client.ext'))
		items.concat(self.ext_aliases.dump_alias_tree('client'))

		return items.sort
	end

	attr_reader   :ext
protected
	attr_accessor :sock, :parser, :ext_aliases
	attr_writer   :ext
end

end; end; end
