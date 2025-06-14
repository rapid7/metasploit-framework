# -*- coding: binary -*-

require 'rex'

module Msf



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
    @routes = RouteArray.new(self)
    #self.routes = []
  end

  # Direct descendants
  # Provider interfaces
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
    "#<Session:#{self.type} #{self.tunnel_peer} (#{self.session_host}) #{self.info ? "\"#{self.info.to_s}\"" : nil}>"  # " Fixes highlighting
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

  def comm_channel
  end

  #
  # Returns the host associated with the session
  #
  def session_host
    # Prefer the overridden session host or target_host
    host = @session_host || self.target_host
    return host if host

    # Fallback to the tunnel_peer (contains port)
    peer = self.tunnel_peer
    return if not peer

    # Pop off the trailing port number
    bits = peer.split(':')
    bits.pop
    bits.join(':')
  end

  #
  # Override the host associated with this session
  #
  def session_host=(v)
    @session_host = v
  end

  #
  # Returns the port associated with the session
  #
  def session_port
    port = @session_port || self.target_port
    return port if port
    # Fallback to the tunnel_peer (contains port)
    peer = self.tunnel_peer
    return if not peer

    # Pop off the trailing port number
    bits = peer.split(':')
    port = bits.pop
    port.to_i
  end

  #
  # Override the host associated with this session
  #
  def session_port=(v)
    @session_port = v
  end

  #
  # Returns a pretty representation of the tunnel.
  #
  def tunnel_to_s
    tunnel_str = "#{tunnel_local || '??'} -> #{tunnel_peer || '??'}"
    tunnel_str << " #{comm_channel}" if comm_channel
    tunnel_str
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
    rhost = session_host.gsub(':', '_')
    sname = name.to_s.gsub(/\W+/,'_')

    "#{dstr}_#{sname}_#{rhost}_#{type}"
  end

  #
  # Returns the log source that should be used for this session.
  #
  def log_source
    "session_#{name}"
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
  # exploit instance. Store references from and to the exploit module.
  #
  def set_from_exploit(m)
    target_host = nil
    unless m.target_host.blank?
      # only propagate the target_host value if it's exactly 1 host
      if (rw = Rex::Socket::RangeWalker.new(m.target_host)).length == 1
        target_host = rw.next_ip
      end
    end

    self.via = { 'Exploit' => m.fullname }
    self.via['Payload'] = ('payload/' + m.datastore['PAYLOAD'].to_s) if m.datastore['PAYLOAD']
    self.target_host = target_host
    self.target_port = m.target_port if (m.target_port.to_i != 0)
    self.workspace   = m.workspace
    self.username    = m.owner
    self.exploit_datastore = m.datastore
    self.user_input = m.user_input if m.user_input
    self.user_output = m.user_output if m.user_output
    self.exploit_uuid = m.uuid
    self.exploit = m
    if m[:task]
      self.exploit_task = m[:task]
    end
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
  # NOTE: session classes overriding this method must call super!
  # Also must tolerate being called multiple times.
  #
  def cleanup
    if db_record and framework.db.active
      ::ApplicationRecord.connection_pool.with_connection do
        framework.db.update_session(id: db_record.id, closed_at: Time.now.utc, close_reason: db_record.close_reason)
      rescue ActiveRecord::RecordNotFound
        nil  # this will fail if the workspace was deleted before the session was closed, see #18561
      end
    end
  end

  #
  # By default, sessions are not interactive.
  #
  def interactive?
    false
  end


  #
  # Allow the session to skip registration
  #
  def register?
    true
  end

  #
  # Allow the user to terminate this session
  #
  def kill
    framework.sessions.deregister(self) if register?
  end

  def dead?
    (not self.alive)
  end

  def alive?
    (self.alive)
  end

  #
  # Get an arch/platform combination
  #
  def session_type
    # avoid unnecessary slash separator
    if !self.arch.nil? && !self.arch.empty? && !self.platform.nil? && !self.platform.empty?
      separator =  '/'
    else
      separator = ''
    end

    "#{self.arch}#{separator}#{self.platform}"
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
  # The original target port if applicable
  #
  attr_accessor :target_port
  #
  # The datastore of the exploit that created this session
  #
  attr_accessor :exploit_datastore
  #
  # The task that ran the exploit that got the session (that swallowed the fly)
  #
  attr_accessor :exploit_task
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
  # The unique identifier of the payload that created this session
  #
  attr_accessor :payload_uuid
  #
  # The unique machine identifier for the host that created this session
  #
  attr_accessor :machine_id
  #
  # The actual exploit module instance that created this session
  #
  attr_accessor :exploit
  #
  # The associated username
  #
  attr_accessor :username
  #
  # An array of routes associated with this session
  #
  attr_accessor :routes
  #
  # This session's associated database record
  #
  attr_accessor :db_record
protected

  attr_accessor :via # :nodoc:

end

end

class RouteArray < Array # :nodoc: all
  def initialize(sess)
    self.session = sess
    super()
  end

  def <<(val)
    session.framework.events.on_session_route(session, val)
    super
  end

  def delete(val)
    session.framework.events.on_session_route_remove(session, val)
    super
  end

  attr_accessor :session
end
