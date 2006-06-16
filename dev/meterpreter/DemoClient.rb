#!/usr/bin/env ruby -I../../lib

require 'Rex/Post'

class DemoClient
	
	def initialize(host, port)
		self.sock   = TCPSocket.new(host, port)
		self.client = Rex::Post::Meterpreter::Client.new(sock)

		self.client.core.use('Stdapi')
	end

	attr_reader   :client
protected
	attr_accessor :sock
	attr_writer   :client

end
