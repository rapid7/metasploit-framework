#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..'))

require 'test/unit'
require 'msf/core/session_manager'

module Msf

class SessionManager::UnitTest < Test::Unit::TestCase

class UtSessionEvent
	include SessionEvent

	def on_session_open(session)
		self.open_session = session
	end
	def on_session_close(session)
		self.close_session = session
	end

	attr_accessor :open_session, :close_session
end

	#
	# Tests to make sure session registration functions properly
	#
	def test_registration
		framework = Framework.new
		manager   = SessionManager.new(framework)

		session   = Class.new
		session.extend(Session)

		assert_equal(1, manager.register(session), "Did not get expected sid")
		assert_equal(1, session.sid, 
			"Session sid was not initialized properly")
		assert_equal(framework, session.framework, 
			"Session framework was not initialized properly")
		assert_equal(1, manager.entries.length, 
			"Number of session manager entries is not one")
		assert_equal(session, manager[session.sid], 
			"Index of sid did not return session")

		manager.deregister(session)
		
		assert_equal(0, manager.entries.length, 
			"Number of session manager entries is not zero")
	end

	#
	# Test session notification events
	#
	def test_notify
		framework = Framework.new
		manager   = SessionManager.new(framework)
		handler   = UtSessionEvent.new
		session   = Class.new
		session.extend(Session)

		framework.events.add_session_subscriber(handler)

		manager.register(session)
		assert_equal(handler.open_session, session, 
			"Open session handler not called")

		manager.deregister(session)
		assert_equal(handler.close_session, session, 
			"Close session handler not called")
	end

end

end