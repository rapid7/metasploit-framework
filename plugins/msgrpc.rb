#!/usr/bin/env ruby
#
# $Id$
#
# This plugin provides an msf daemon interface that spawns a listener on a
# defined port (default 55552) and gives each connecting client its own
# console interface.  These consoles all share the same framework instance.
# Be aware that the console instance that spawns on the port is entirely
# unauthenticated, so realize that you have been warned.
#
# $Revision$
#

require "msf/core/rpc/v10/service"
require "fileutils"

module Msf

###
#
# This class implements the msfd plugin interface.
#
###
class Plugin::MSGRPC < Msf::Plugin

	#
	# The default local hostname that the server listens on.
	#
	DefaultHost = "127.0.0.1"

	#
	# The default local port that the server listens on.
	#
	DefaultPort = 55552

	#
	# ServerPort
	#
	# 	The local port to listen on for connections.  The default is 55553
	#
	def initialize(framework, opts)
		super

		host = opts['ServerHost'] || DefaultHost
		port = opts['ServerPort'] || DefaultPort
		ssl  = (opts['SSL'] and opts['SSL'].to_s =~ /^[ty]/i) ? true : false
		cert = opts['SSLCert']

		user = opts['User'] || "msf"
		pass = opts['Pass'] || ::Rex::Text.rand_text_alphanumeric(8)
		uri  = opts['URI'] || "/api"

		print_status("MSGRPC Service:  #{host}:#{port} #{ssl ? " (SSL)" : ""}")
		print_status("MSGRPC Username: #{user}")
		print_status("MSGRPC Password: #{pass}")

		self.server	= ::Msf::RPC::Service.new(framework, {
			:host   => host,
			:port   => port,
			:ssl    => ssl,
			:cert   => cert,
			:uri    => uri,
			:tokens => { }
		})

		self.server.add_user(user, pass)

		# If the run in foreground flag is not specified, then go ahead and fire
		# it off in a worker thread.
		if (opts['RunInForeground'] != true)
			# Store a handle to the thread so we can kill it during
			# cleanup when we get unloaded.
			self.thread = framework.threads.spawn("MetasploitRPCServer", true) {
        run
      }
		end
	end

	#
	# Returns 'msgrpc'
	#
	def name
		"msgrpc"
	end

	#
	# Returns the plugin description.
	#
	def desc
		"Provides a MessagePack interface over HTTP"
	end

	#
	# The meat of the plugin, sets up handlers for requests
	#
	def run
		# Start the actual service
		self.server.start

    # Wait for the service to complete
    wait = -> { server.wait }

    if framework.threads.registered?
      # if run is called inside of framework.threads.spawn, thread cannot re-register, so just wait since already in
      # spawned thread.
      wait.call
    else
      framework.threads.register(
          block: wait,
          critical: true,
          name: 'MetasploitRPCServer'
      )
    end
	end

	#
	# Closes the listener service.
	#
	def cleanup
		self.server.stop if self.server
		self.thread.kill if self.thread
		self.server = nil
		super
	end

	#
	# The MSGRPC instance.
	#
	attr_accessor :server
	attr_accessor :thread
	attr_accessor :users
	attr_accessor :tokens

end

end

