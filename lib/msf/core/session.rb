require 'msf/core'

module Msf

###
#
# SessionEvents
# -------------
#
# Event notifications that affect sessions.
#
###
module SessionEvents

	# Called when a session is opened
	def on_session_open(session)
	end

	# Called when a session is closed
	def on_session_close(session)
	end

end

###
#
# Session
# -------
#
# The session class represents a post-exploitation, uh, session.
# Sessions can be written to, read from, and interacted with.  The
# underlying medium on which they are backed is arbitrary.  For 
# instance, when an exploit is provided with a command shell,
# either through a network connection or locally, the session's
# read and write operations end up reading from and writing to
# the shell that was spawned.  The session object can be seen
# as a general means of interacting with various post-exploitation
# payloads through a common interface that is not necessarily 
# tied to a network connection.
#
###
module Session

	include Framework::Offspring

	# Direct descendents
	require 'msf/core/session/interactive'
	require 'msf/core/session/basic'

	# Provider interfaces
	require 'msf/core/session/provider/single_command_execution'
	require 'msf/core/session/provider/multi_command_execution'
	require 'msf/core/session/provider/single_command_shell'
	require 'msf/core/session/provider/multi_command_shell'

	#
	# By default, sessions are not interactive.
	#
	def interactive?
		false
	end

	#
	# Perform session-specific cleanup
	#
	def cleanup
	end

	#
	# Returns the session's name if it's been assigned one, otherwise
	# the sid is returned.
	#
	def sname
		return name || sid
	end

	#
	# Sets the session's name
	#
	def sname=(name)
		self.name = name
	end

	attr_accessor :framework, :sid, :name

protected

end

end
