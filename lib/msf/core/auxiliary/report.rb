module Msf

###
#
# This module provides methods for reporting data to the DB
#
###

module Auxiliary::Report


	def initialize(info = {})
		super
	end

	# Shortcut method for detecting when the DB is active
	def db
		framework.db.active
	end

	def myworkspace
		return @myworkspace if @myworkspace
		@myworkspace = framework.db.find_workspace(self.workspace)
	end

	#
	# Report a host's liveness and attributes such as operating system and service pack
	#
	# opts must contain :host, which is an IP address identifying the host
	# you're reporting about
	#
	# See data/sql/*.sql and lib/msf/core/db.rb for more info
	#
	def report_host(opts)
		return if not db
		opts = {:workspace => myworkspace}.merge(opts)
		framework.db.report_host(opts)
	end

	def get_host(opts)
		return if not db
		opts = {:workspace => myworkspace}.merge(opts)
		framework.db.get_host(opts)
	end

	#
	# Report a client connection
	#
	# opts must contain
	#	:host      the address of the client connecting
	#	:ua_string a string that uniquely identifies this client
	# opts can contain
	#	:ua_name a brief identifier for the client, e.g. "Firefox"
	#	:ua_ver  the version number of the client, e.g. "3.0.11"
	#
	def report_client(opts={})
		return if not db
		opts = {:workspace => myworkspace}.merge(opts)
		framework.db.report_client(opts)
	end

	def get_client(opts={})
		return if not db
		opts = {:workspace => myworkspace}.merge(opts)
		framework.db.get_client(opts)
	end

	#
	# Report detection of a service
	#
	def report_service(opts={})
		return if not db
		opts = {:workspace => myworkspace}.merge(opts)
		framework.db.report_service(opts)
	end

	def report_note(opts={})
		return if not db
		opts = {:workspace => myworkspace}.merge(opts)
		framework.db.report_note(opts)
	end

	def report_auth_info(opts={})
		return if not db
		opts = {:workspace => myworkspace}.merge(opts)
		framework.db.report_auth_info(opts)
	end

	def report_vuln(opts={})
		return if not db
		opts = {:workspace => myworkspace}.merge(opts)
		framework.db.report_vuln(opts)
	end

	def report_loot(opts={})
		return if not db
		opts = {:workspace => myworkspace}.merge(opts)
		framework.db.report_loot(opts)
	end

end
end

