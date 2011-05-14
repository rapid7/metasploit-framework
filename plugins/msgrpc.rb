#!/usr/bin/env ruby
#
# $Id$
#
# This plugin provides an msf daemon interface that spawns a listener on a
# defined port (default 55553) and gives each connecting client its own
# console interface.  These consoles all share the same framework instance.
# Be aware that the console instance that spawns on the port is entirely
# unauthenticated, so realize that you have been warned.
#
# $Revision$
#

require "msf/core/rpc"
require "msf/core/rpc/service_msgpack"
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
		ckey = opts['SSLKey']

		user = opts['User'] || "msf"
		pass = opts['Pass'] || ::Rex::Text.rand_text_alphanumeric(8)
		type = opts['ServerType'] || "Basic"
		uri  = opts['URI'] || "/api"

		print_status("MSGRPC Service:  #{host}:#{port} #{ssl ? " (SSL)" : ""}")
		print_status("MSGRPC Username: #{user}")
		print_status("MSGRPC Password: #{pass}")

		@users = [ [user,pass] ]

		self.server	= ::Msf::RPC::MessagePackService.new(host,port,{
			:ssl  => opts['SSL'],
			:cert => opts['SSLCert'],
			:key  => opts['SSLKey'],
			:uri  => opts['URI']
		})
	

		# If the run in foreground flag is not specified, then go ahead and fire
		# it off in a worker thread.
		if (opts['RunInForeground'] != true)
			# Store a handle to the thread so we can kill it during
			# cleanup when we get unloaded.
			self.thread = Thread.new {
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

		# Initialize the list of authenticated sessions
		@tokens = {}

		args = [framework, @tokens, @users]

		# Add handlers for every class
		self.server.add_handler("auth",
			::Msf::RPC::Auth.new(*args)
		)

		# Note the extra argument for core as compared to the other
		# handlers.  This allows rpc clients access to the plugin so
		# they can shutdown the server.
		core_args = args + [self]
		self.server.add_handler("core",
			::Msf::RPC::Core.new(*core_args)
		)

		self.server.add_handler("session",
			::Msf::RPC::Session.new(*args)
		)

		self.server.add_handler("job",
			::Msf::RPC::Job.new(*args)
		)

		self.server.add_handler("module",
			::Msf::RPC::Module.new(*args)
		)

		self.server.add_handler("console",
			::Msf::RPC::Console.new(*args)
		)

		self.server.add_handler("db",
			::Msf::RPC::Db.new(*args)
		)

		self.server.add_handler("plugin",
			::Msf::RPC::Plugin.new(*args)
		)

		# Start the actual service
		self.server.start
	
		# Wait for the service to complete
		
		self.server.wait
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

	def stop_rpc
		print_line
		print_status("MSGRPC Client requested server stop")
		# Plugins aren't really meant to be able to unload themselves, so this
		# is a bit of a corner case.  Unloading ourselves ends up killing the
		# thread that's doing the unloading so we need to fire off the unload
		# in a seperate one.
		Thread.new {
			framework.plugins.unload(self)
		}
		nil
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

