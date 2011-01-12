require 'msf/core'
require 'msf/core/module'

module Msf
class Post < Msf::Module

	include Msf::Auxiliary::Report

	def self.type
		MODULE_POST
	end
	def type
		MODULE_POST
	end

	def initialize(info={})
		super

		register_options( [
			OptInt.new('SESSION', [ true, "The session to run this module on." ])
		] , Msf::Post)
	end

	#
	# Grabs a session object from the framework or raises OptionValidateError
	# if one doesn't exist.
	#
	def setup
		@sysinfo = nil
		@session = framework.sessions[datastore["SESSION"].to_i]
		@session ||= framework.sessions[datastore["SESSION"].to_s]
		if not @session
			raise Msf::OptionValidateError.new(["SESSION"])
		end
		@session.init_ui(self.user_input, self.user_output)
	end

	#
	# Default cleanup handler does nothing
	#
	def cleanup
	end

	def session
		@session
	end

	def client
		@session
	end

	def platform
		return session.platform if session
		super
	end

	# 
	# Cached sysinfo, returns nil for non-meterpreter sessions
	#
	def sysinfo
		begin
			@sysinfo ||= session.sys.config.sysinfo
		rescue NoMethodError
			@sysinfo = nil
		end
		@sysinfo
	end

	#
	# Can be overridden by individual modules to add new commands
	#
	def post_commands
		{}
	end

	#
	# Default stance is active
	#
	def passive
		false
	end

	def compatible_sessions
		sessions = []
		framework.sessions.each do |sid, s|
			next unless self.module_info["SessionTypes"].include?(s.type)
			sessions << sid
		end
		sessions
	end


end
end

