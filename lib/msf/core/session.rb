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

	def initialize(framework, sid, stream = nil)
		self.framework = framework
		self.stream    = stream
		self.sid       = sid

		# Call the framework event dispatcher to let it know that we've
		# opened a new session
		framework.events.on_session_open(self)
	end

	# Read length supplied bytes from the stream
	def read(length = nil)
		return stream.read(length)
	end

	# Write the supplied buffer to the stream
	def write(buf)
		return stream.write(buf)
	end

	# Close the session's stream and perform cleanup as necessary
	def close
		# Call the framework event dispatcher to let it know that we've
		# closed a session
		framework.events.on_session_close(self)

		return stream.close
	end

	attr_reader   :sid, :stream

protected

	attr_writer   :sid, :stream
	attr_accessor :framework
end

#
#
# Built-in session classes
#
#

###
#
# ShellSession
# ------------
#
# This class represents a session that is associated with a command
# interpreter.  Its read and write operations interact with whatever
# command interpreter it is backed against, whether it be local or
# otherwise.
#
###
class ShellSession < Session

end

end
