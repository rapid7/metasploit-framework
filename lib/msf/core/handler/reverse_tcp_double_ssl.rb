# -*- coding: binary -*-
require 'msf/core/handler/reverse_tcp_double'
module Msf
module Handler

###
#
# This module implements the reverse double TCP SSL handler. This means
# that it listens on a port waiting for a two connections, one connection
# is treated as stdin, the other as stdout.
#
# This handler depends on having a local host and port to
# listen on.
#
###
module ReverseTcpDoubleSsl

	include Msf::Handler::ReverseTcpDouble

	#
	# Returns the string representation of the handler type, in this case
	#
	def self.handler_type
		return "reverse_tcp_double_ssl"
	end

	#
	# Returns the connection-described general handler type, in this case
	# 'reverse'.
	#
	def self.general_handler_type
		"reverse"
	end

	#
	# Initializes the reverse TCP handler and ads the options that are required
	# for all reverse TCP payloads, like local host and local port.
	#
	def initialize(info = {})
		super

		# XXX: Not supported by all modules
		register_advanced_options(
			[
				OptPath.new('SSLCert',    [ false, 'Path to a custom SSL certificate (default is randomly generated)'])
			], Msf::Handler::ReverseTcpDoubleSsl)
	end

	#
	# Starts the listener but does not actually attempt
	# to accept a connection.  Throws socket exceptions
	# if it fails to start the listener.
	#
	def setup_handler
		if datastore['Proxies']
			raise 'tcp connectback can not be used with proxies'
		end

		comm.extend(Rex::Socket::SslTcp)
		self.listener_sock = Rex::Socket::SslTcpServer.create(
		'LocalHost' => datastore['LHOST'],
		'LocalPort' => datastore['LPORT'].to_i,
		'Comm'      => comm,
		'SSLCert'	=> datastore['SSLCert'],
		'Context'   =>
			{
				'Msf'        => framework,
				'MsfPayload' => self,
				'MsfExploit' => assoc_exploit
			})
	end


end
end
end
