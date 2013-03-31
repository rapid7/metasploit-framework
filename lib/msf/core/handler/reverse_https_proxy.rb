# -*- coding: binary -*-
require 'rex/io/stream_abstraction'
require 'rex/sync/ref'
require 'msf/core/handler/reverse_http'

module Msf
module Handler

###
#
# This handler implements the HTTP SSL tunneling interface.
#
###
module ReverseHttpsProxy

	include Msf::Handler::ReverseHttp

	#
	# Returns the string representation of the handler type
	#
	def self.handler_type
		return "reverse_https_proxy"
	end

	#
	# Returns the connection-described general handler type, in this case
	# 'tunnel'.
	#
	def self.general_handler_type
		"tunnel"
	end

	#
	# Initializes the HTTP SSL tunneling handler.
	#
	def initialize(info = {})
		super

		register_options(
			[
				OptPort.new('LPORT', [ true, "The local listener port", 8443 ])
			], Msf::Handler::ReverseHttpsProxy)

	end

end

end
end

