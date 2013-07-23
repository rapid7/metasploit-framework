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
				OptString.new('LHOST', [ true, "The local listener hostname" ,"127.0.0.1"]),
				OptPort.new('LPORT', [ true, "The local listener port", 8443 ]),
				OptString.new('PROXYHOST', [true, "The address of the http proxy to use" ,"127.0.0.1"]),
				OptInt.new('PROXYPORT', [ false, "The Proxy port to connect to", 8080 ]),
				OptString.new('HIDDENHOST', [false, "The tor hidden host to connect to, when set it will be used instead of LHOST for stager generation"]),
				OptInt.new('HIDDENPORT', [ false, "The hidden port to connect to, when set it will be used instead of LPORT for stager generation"]),
				OptEnum.new('PROXY_TYPE', [true, 'Http or Socks4 proxy type', 'HTTP', ['HTTP', 'SOCKS']]),
				OptString.new('PROXY_USERNAME', [ false, "An optional username for HTTP proxy authentification"]),
				OptString.new('PROXY_PASSWORD', [ false, "An optional password for HTTP proxy authentification"])
 			], Msf::Handler::ReverseHttpsProxy)

	end

end

end
end

