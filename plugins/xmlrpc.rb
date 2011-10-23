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
require "fileutils"

module Msf

###
#
# This class implements the msfd plugin interface.
#
###
class Plugin::XMLRPC < Msf::Plugin

	#
	# The default local hostname that the server listens on.
	#
	DefaultHost = "127.0.0.1"

	#
	# The default local port that the server listens on.
	#
	DefaultPort = 55553

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
		uri  = opts['URI'] || "/RPC2"

		print_status("XMLRPC Service:  #{host}:#{port} #{ssl ? " (SSL)" : ""}")
		print_status("XMLRPC Username: #{user}")
		print_status("XMLRPC Password: #{pass}")
		print_status("XMLRPC Server Type: #{type}")

		@users = [ [user,pass] ]
		if(type =~ /Web/i)
			print_status("XMLRPC Web URI: #{uri}")
			self.server	= ::Msf::RPC::WebService.new(port,host,uri)
		elsif(type =~ /Basic/i)
			self.server	= ::Msf::RPC::Service.new(host,port,ssl,cert,ckey)
		else
			print_status("Invalid server type #{type}, please choose Web or Basic")
		end

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
	# Returns 'xmlrpc'
	#
	def name
		"xmlrpc"
	end

	#
	# Returns the plugin description.
	#
	def desc
		"Provides a XMLRPC interface over a listening TCP port."
	end

	#
	# The meat of the plugin, sets up handlers for requests
	#
	def run

		# Initialize the list of authenticated sessions
		@tokens = {}

		args = [framework,@tokens,@users]

		# Add handlers for every class
		self.server.add_handler(::XMLRPC::iPIMethods("auth"),
			::Msf::RPC::Auth.new(*args)
		)

		# Note the extra argument for core as compared to the other
		# handlers.  This allows rpc clients access to the plugin so
		# they can shutdown the server.
		core_args = args + [self]
		self.server.add_handler(::XMLRPC::iPIMethods("core"),
			::Msf::RPC::Core.new(*core_args)
		)

		self.server.add_handler(::XMLRPC::iPIMethods("session"),
			::Msf::RPC::Session.new(*args)
		)

		self.server.add_handler(::XMLRPC::iPIMethods("job"),
			::Msf::RPC::Job.new(*args)
		)

		self.server.add_handler(::XMLRPC::iPIMethods("module"),
			::Msf::RPC::Module.new(*args)
		)

		self.server.add_handler(::XMLRPC::iPIMethods("console"),
			::Msf::RPC::Console.new(*args)
		)

		self.server.add_handler(::XMLRPC::iPIMethods("db"),
			::Msf::RPC::Db.new(*args)
		)

		self.server.add_handler(::XMLRPC::iPIMethods("plugin"),
			::Msf::RPC::Plugin.new(*args)
		)

		# Set the default/catch-all handler
		self.server.set_default_handler do |name, *args|
			raise ::XMLRPC::FaultException.new(-99, "Method #{name} missing or wrong number of parameters!")
		end

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
		print_status("XMLRPC Client requested server stop")
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
	# The XMLRPC instance.
	#
	attr_accessor :server
	attr_accessor :thread
	attr_accessor :users
	attr_accessor :tokens

end

end

