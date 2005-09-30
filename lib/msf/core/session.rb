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
	require 'msf/core/session/comm'

	# Provider interfaces
	require 'msf/core/session/provider/single_command_execution'
	require 'msf/core/session/provider/multi_command_execution'
	require 'msf/core/session/provider/single_command_shell'
	require 'msf/core/session/provider/multi_command_shell'

	def self.type
		"unknown"
	end

	#
	# Returns the session's name if it's been assigned one, otherwise
	# the sid is returned.
	#
	def name
		return sname || sid
	end

	#
	# Sets the session's name
	#
	def name=(name)
		self.sname = name
	end

	#
	# Returns the description of the session
	#
	def desc
	end

	#
	# Returns the type of session in use
	#
	def type
	end

	#
	# Returns the local side of the tunnel
	#
	def tunnel_local
	end

	#
	# Returns the peer side of the tunnel
	#
	def tunnel_peer
	end

	#
	# Returns a pretty representation of the tunnel
	#
	def tunnel_to_s
		"#{(tunnel_local || '??').to_s} -> #{(tunnel_peer || '??').to_s}"
	end

	##
	#
	# Core interface
	#
	##

	#
	# Sets the vector through which this session was realized
	#
	def set_via(opts)
		self.via = opts || {}	
	end

	#
	# Returns the exploit module name through which this session was
	# created.
	#
	def via_exploit
		self.via['Exploit'] if (self.via)
	end

	#
	# Returns the payload module name through which this session was
	# created.
	#
	def via_payload
		self.via['Payload'] if (self.via)
	end

	#
	# Perform session-specific cleanup.
	#
	def cleanup
	end

	#
	# By default, sessions are not interactive.
	#
	def interactive?
		false
	end

	attr_accessor :framework, :sid, :sname

protected

	attr_accessor :via

end

end
