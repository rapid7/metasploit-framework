require 'Msf/Core'

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
# Sessions can be written from, read to, and interacted with.  The
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
class Session

	def initialize()
	end

	#
	# Perform session-specific cleanup
	#
	def cleanup
	end

	attr_accessor :framework, :sid

protected

end

end

# 
# Require the individual provider interfaces
#
require 'Msf/Core/SessionProvider/SingleCommandExecution'
require 'Msf/Core/SessionProvider/MultiCommandExecution'
require 'Msf/Core/SessionProvider/SingleCommandShell'
require 'Msf/Core/SessionProvider/MultiCommandShell'
