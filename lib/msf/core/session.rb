require 'msf/core'

module Msf

###
#
# Event notifications that affect sessions.
#
###
module SessionEvent

	#
	# Called when a session is opened.
	#
	def on_session_open(session)
	end

	#
	# Called when a session is closed.
	#
	def on_session_close(session, reason='')
	end

	#
	# Called when the user interacts with a session.
	#
	def on_session_interact(session)
	end

	#
	# Called when the user writes data to a session.
	#
	def on_session_command(session, command)
	end

	#
	# Called when output comes back from a user command.
	#
	def on_session_output(session, output)
	end

	#
	# Called when a file is uploaded.
	#
	def on_session_upload(session, local_path, remote_path)
	end

	#
	# Called when a file is downloaded.
	#
	def on_session_download(session, remote_path, local_path)
	end

	#
	# Called when a file is deleted.
	#
	def on_session_filedelete(session, path)
	end
end

###
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

	def initialize
		self.alive = true
		self.uuid  = Rex::Text.rand_text_alphanumeric(8).downcase
	end

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
	# Sets the session's name.
	#
	def name=(name)
		self.sname = name
	end

	#
	# Brief and to the point
	#
	def inspect
		"#<Session:#{self.type} #{self.tunnel_peer || self.tunnel_peer} #{self.info.to_s}>"
	end

	#
	# Returns the description of the session.
	#
	def desc
	end

	#
	# Returns the type of session in use.
	#
	def type
	end

	#
	# Returns the local side of the tunnel.
	#
	def tunnel_local
	end

	#
	# Returns the peer side of the tunnel.
	#
	def tunnel_peer
	end

	#
	# Returns a pretty representation of the tunnel.
	#
	def tunnel_to_s
		"#{(tunnel_local || '??')} -> #{(tunnel_peer || '??')}"
	end

	##
	#
	# Logging
	#
	##

	#
	# Returns the suggested name of the log file for this session.
	#
	def log_file_name
		dt = Time.now

		dstr  = sprintf("%.4d%.2d%.2d", dt.year, dt.mon, dt.mday)
		rhost = (tunnel_peer || 'unknown').split(':')[0]

		"#{dstr}_#{rhost}_#{type}"
	end

	#
	# Returns the log source that should be used for this session.
	#
	def log_source
		"session_#{name}"
	end

	#
	# This method logs the supplied buffer as coming from the remote side of
	# the session.
	#
	def log_from_remote(buf)
		rlog(buf, log_source)
	end

	#
	# This method logs the supplied buffer as coming from the local side of
	# the session.
	#
	def log_from_local(buf)
		rlog(buf, log_source)
	end

	##
	#
	# Core interface
	#
	##

	#
	# Sets the vector through which this session was realized.
	#
	def set_via(opts)
		self.via = opts || {}
	end

	#
	# Configures via_payload, via_payload, workspace, target_host from an
	# exploit instance.
	#
	def set_from_exploit(m)
		self.via = { 'Exploit' => m.fullname }
		self.via['Payload'] = ('payload/' + m.datastore['PAYLOAD'].to_s) if m.datastore['PAYLOAD']

		self.target_host = m.target_host
		self.workspace   = m.workspace
		self.username    = m.owner
		self.exploit_datastore = m.datastore.dup
		self.user_input = m.user_input if m.user_input
		self.user_output = m.user_output if m.user_output
		self.exploit_uuid = m.uuid
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


	#
	# Allow the user to terminate this session
	#
	def kill
		framework.sessions.deregister(self)
	end

	def dead?
		(not self.alive)
	end
	def alive?
		(self.alive)
	end

	attr_accessor :alive

	#
	# The framework instance that created this session.
	#
	attr_accessor :framework
	#
	# The session unique identifier.
	#
	attr_accessor :sid
	#
	# The session name.
	#
	attr_accessor :sname
	#
	# The associated workspace name
	#
	attr_accessor :workspace
	#
	# The original target host address
	#
	attr_accessor :target_host
	#
	# The datastore of the exploit that created this session
	#
	attr_accessor :exploit_datastore
	#
	# The specific identified session info
	#
	attr_accessor :info
	#
	# The unique identifier of this session
	#
	attr_accessor :uuid
	#
	# The unique identifier of exploit that created this session
	#
	attr_accessor :exploit_uuid
	#
	# The associated username
	#
	attr_accessor :username
protected

	attr_accessor :via # :nodoc:

end

end

