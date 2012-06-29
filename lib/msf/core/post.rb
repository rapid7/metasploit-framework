# -*- coding: binary -*-
require 'msf/core'
require 'msf/core/module'

module Msf
class Post < Msf::Module

	include Msf::Auxiliary::Report

	include Msf::Module::HasActions

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

		# Default stance is active
		self.passive = (info['Passive'] and info['Passive'] == true) || false
	end

	#
	# Grabs a session object from the framework or raises OptionValidateError
	# if one doesn't exist.  Initializes user input and output on the session.
	#
	def setup
		@sysinfo = nil
		if not session
			raise Msf::OptionValidateError.new(["SESSION"])
		end
		check_for_session_readiness() if session.type == "meterpreter"

		@session.init_ui(self.user_input, self.user_output)
	end

	# Meterpreter sometimes needs a little bit of extra time to
	# actually be responsive for post modules. Default tries
	# and retries for 5 seconds.
	def check_for_session_readiness(tries=6)
		session_ready_count = 0
		session_ready = false
		until session.sys or session_ready_count > tries
			session_ready_count += 1
			back_off_period = (session_ready_count**2)/10.0
			select(nil,nil,nil,back_off_period)
		end
		session_ready = !!session.sys
		raise "Could not get a hold of the session." unless session_ready
		return session_ready
	end

	#
	# Default cleanup handler does nothing
	#
	def cleanup
	end

	#
	# Return the associated session or nil if there isn't one
	#
	def session
		# Try the cached one
		return @session if @session and not session_changed?

		if datastore["SESSION"]
			@session = framework.sessions[datastore["SESSION"].to_i]
		else
			@session = nil
		end

		@session
	end

	alias :client :session

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

	def passive?
		self.passive
	end

	#
	# Return a (possibly empty) list of all compatible sessions
	#
	def compatible_sessions
		sessions = []
		framework.sessions.each do |sid, s|
			sessions << sid if session_compatible?(s)
		end
		sessions
	end

	#
	# Create an anonymous module not tied to a file.  Only useful for IRB.
	#
	def self.create(session)
		mod = new
		mod.instance_variable_set(:@session, session)
		# Have to override inspect because for whatever reason, +type+ is coming
		# from the wrong scope and i can't figure out how to fix it.
		mod.instance_eval do
			def inspect
				"#<Msf::Post anonymous>"
			end
		end
		mod.class.refname = "anonymous"

		mod
	end

	#
	# Return false if the given session is not compatible with this module
	#
	# Checks the session's type against this module's
	# +module_info["SessionTypes"]+ as well as examining platform
	# compatibility.  +sess_or_sid+ can be a Session object, Fixnum, or String.
	# In the latter cases it sould be a key in in +framework.sessions+.
	#
	# NOTE: because it errs on the side of compatibility, a true return value
	# from this method does not guarantee the module will work with the
	# session.
	#
	def session_compatible?(sess_or_sid)
		# Normalize the argument to an actual Session
		case sess_or_sid
		when ::Fixnum, ::String
			s = framework.sessions[sess_or_sid.to_i]
		when ::Msf::Session
			s = sess_or_sid
		end

		# Can't do anything without a session
		return false if s.nil?

		# Can't be compatible if it's the wrong type
		if self.module_info["SessionTypes"]
			return false unless self.module_info["SessionTypes"].include?(s.type)
		end

		# XXX: Special-case java and php for now.  This sucks and Session
		# should have a method to auto-detect the underlying platform of
		# platform-independent sessions such as these.
		plat = s.platform
		if plat =~ /php|java/ and sysinfo and sysinfo["OS"]
			plat = sysinfo["OS"]
		end

		# Types are okay, now check the platform.  This is kind of a ghetto
		# workaround for session platforms being ad-hoc and Platform being
		# inflexible.
		if self.platform and self.platform.kind_of?(Msf::Module::PlatformList)
			[
				# Add as necessary
				"win", "linux", "osx"
			].each do |name|
				if plat =~ /#{name}/
					p = Msf::Module::PlatformList.transform(name)
					return false unless self.platform.supports? p
				end
			end
		elsif self.platform and self.platform.kind_of?(Msf::Module::Platform)
			p_klass = Msf::Module::Platform
			case plat.downcase
			when /win/
				return false unless self.platform.kind_of?(p_klass::Windows)
			when /osx/
				return false unless self.platform.kind_of?(p_klass::OSX)
			when /linux/
				return false unless self.platform.kind_of?(p_klass::Linux)
			end
		end

		# If we got here, we haven't found anything that definitely
		# disqualifies this session.  Assume that means we can use it.
		return true
	end

	#
	# True when this module is passive, false when active
	#
	attr_reader :passive

protected

	attr_writer :passive

	def session_changed?
		@ds_session ||= datastore["SESSION"]

		if (@ds_session != datastore["SESSION"])
			@ds_session = nil
			return true
		else
			return false
		end
	end
end
end

