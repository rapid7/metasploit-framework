#!/usr/bin/ruby

require 'socket'
require 'Rex/Post/Meterpreter/ClientCore'
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

	def initialize(sock)
		self.sock        = sock
		self.parser      = PacketParser.new
		self.ext         = ObjectAliases.new
		self.ext_aliases = ObjectAliases.new

		self.register_extension_alias('core', ClientCore.new(self))

		monitor_socket
	end

	# 
	# Accessors
	#
	def Client.default_timeout
		return 30
	end

	#
	# Alias processor
	#
	def method_missing(symbol, *args)
		return self.ext_aliases.aliases[symbol.to_s];
	end

	#
	# Extension registration
	#
	def add_extension(name)
		if (Kernel.require("Rex/Post/Meterpreter/Extensions/#{name}/#{name}") == false)
			return false
		end

		ext = eval("Rex::Post::Meterpreter::Extensions::" + name + "::" + name + ".new(self)")

		self.ext.aliases[ext.name] = ext

		return true
	end

	def deregister_extension(name)
		self.ext.aliases.delete(name)
	end

	def each_extension(&block)
		self.ext.aliases.each(block)
	end

	def register_extension_alias(name, ext)
		self.ext_aliases.aliases[name] = ext
	end

	def deregister_extension_alias(name)
		self.ext_aliases.aliases.delete(name)
	end

	attr_reader   :ext
	protected
	attr_accessor :sock, :parser, :ext_aliases
	attr_writer   :ext
end

end; end; end
