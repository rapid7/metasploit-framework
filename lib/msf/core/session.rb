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

	def initialize(conn = nil)
		self.conn = conn
	end

	#
	# Read length supplied bytes from the conn
	#
	def read(length = nil)
		return conn.read(length)
	end

	#
	# Write the supplied buffer to the conn
	#
	def write(buf)
		return conn.write(buf)
	end

	#
	# Close the session's conn and perform cleanup as necessary
	#
	def close
		return conn.close
	end

	attr_reader   :conn
	attr_accessor :framework, :sid

protected

	attr_writer   :conn
end

end
