#!/usr/bin/ruby

require 'socket'
require 'Rex/Post/Meterpreter/ClientCore'
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
		self.sock   = sock
		self.parser = PacketParser.new
		self.core   = ClientCore.new(self)

		monitor_socket
	end

	def brand(klass)
		klass = klass.dup
		klass.client = self
		return klass
	end

	attr_reader   :core
	protected
	attr_accessor :sock, :parser
	attr_writer   :core
end

end; end; end
