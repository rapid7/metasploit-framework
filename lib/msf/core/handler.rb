# -*- coding: binary -*-
require 'msf/core'

module Msf

###
#
# This module acts as a base for all handler pseudo-modules.  They aren't
# really modules, so don't get the wrong idea champs!  They're merely
# mixed into dynamically generated payloads to handle monitoring for
# a connection.  Handlers are layered in between the base payload
# class and any other payload class.  A super cool ASCII diagram would
# look something like this
#
#      Module
#        ^
#        |
#     Payload
#        ^
#        |
#     Handler
#        ^
#        |
#      Stager
#        ^
#        |
#       Stage
#
###
module Handler
  require 'msf/core/handler/reverse'

  ##
  #
  # Constants used with the ``handler'' method to indicate whether or not the
  # connection was used.
  #
  ##

  #
  # Returned by handlers to indicate that a socket has been claimed for use
  # by the payload.
  #
  Claimed = "claimed"
  #
  # Returned by handlers to indicate that a socket has not been claimed for
  # use.
  #
  Unused  = "unused"

  #
  # Returns the handler type.
  #
  def self.handler_type
    return "none"
  end

  #
  # Returns the transport-independent handler type.
  #
  def self.general_handler_type
    "none"
  end

  #
  # Returns the handler's name, if any.
  #
  def handler_name
    module_info['HandlerName']
  end

  #
  # Initializes the session waiter event and other fun stuff.
  #
  def initialize(info = {})
    super

    # Initialize the pending_connections counter to 0
    self.pending_connections = 0

    # Initialize the sessions counter to 0
    self.sessions = 0

    # Create the waiter event with auto_reset set to false so that
    # if a session is ever created, waiting on it returns immediately.
    self.session_waiter_event = Rex::Sync::Event.new(false, false)
  end

  #
  # Sets up the connection handler.
  #
  def setup_handler
  end

  #
  # Terminates the connection handler.
  #
  def cleanup_handler
  end

  #
  # Start monitoring for a connection.
  #
  def start_handler
  end

  #
  # Start another connection monitor
  #
  def add_handler(opts={})
  end

  #
  # Stop monitoring for a connection.
  #
  def stop_handler
  end

  #
  # Checks to see if a payload connection has been established on
  # the supplied connection.  This is necessary for find-sock style
  # payloads.
  #
  def handler(sock)
  end

  #
  # Handles an established connection supplied in the in and out
  # handles.  The handles are passed as parameters in case this
  # handler is capable of handling multiple simultaneous
  # connections.  The default behavior is to attempt to create a session for
  # the payload.  This path will not be taken for multi-staged payloads.
  #
  def handle_connection(conn, opts={})
    puts("In Handle Connection")
    create_session(conn, opts)
  end

  #
  # The amount of time to wait for a session to come in.
  #
  def wfs_delay
    2
  end

  #
  # Waits for a session to be created as the result of a handler connection
  # coming in.  The return value is a session object instance on success or
  # nil if the timeout expires.
  #
  def wait_for_session(t = wfs_delay)
    session = nil

    begin
      session = session_waiter_event.wait(t)
    rescue ::Timeout::Error
    end

    # If a connection has arrived, wait longer...
    if (pending_connections > 0)
      session = session_waiter_event.wait
    end

    return session
  end

  #
  # Interrupts a wait_for_session call by notifying with a nil event
  #
  def interrupt_wait_for_session
    return unless session_waiter_event
    session_waiter_event.notify(nil)
  end

  #
  # Set by the exploit module to configure handler
  #
  attr_accessor :exploit_config

  #
  # This will be non-nil if the handler has a parent payload that it
  # was spawned from.  Right now, this is only the case with generic
  # payloads.  The parent payload is used to create a session
  # rather than using the instance itself.
  #
  attr_accessor :parent_payload

protected

  #
  # Creates a session, if necessary, for the connection that's been handled.
  # Sessions are only created if the payload that's been mixed in has an
  # associated session.
  #
  def create_session(conn, opts={})
    puts("In create_session")
    # If there is a parent payload, then use that in preference.
    return parent_payload.create_session(conn, opts) if (parent_payload)
    puts("Past Parent Part")
    puts("WTF?")

    # If the payload we merged in with has an associated session factory,
    # allocate a new session.
    if (self.session)
      begin
        # if there's a create_session method then use it, as this
        # can form a factory for arb session types based on the
        # payload.
        if self.session.respond_to?('create_session')
          puts("create_session")
          s = self.session.create_session(conn, opts)
        else
          puts("new session")
          s = self.session.new(conn, opts)
          puts("Session type = " + s.type) 
        end
      rescue ::Exception => e
        # We just wanna show and log the error, not trying to swallow it.
        print_error("#{e.class} #{e.message}")
        elog("#{e.class} #{e.message}\n#{e.backtrace * "\n"}")
        raise e
      end

      # Pass along the framework context
      s.framework = framework

      # Associate this system with the original exploit
      # and any relevant information
      s.set_from_exploit(assoc_exploit)

      # Pass along any associated payload uuid if specified
      if opts[:payload_uuid]
        s.payload_uuid = opts[:payload_uuid]
        s.payload_uuid.registered = false

        if framework.db.active
          payload_info = {
              uuid: s.payload_uuid.puid_hex,
              workspace: framework.db.workspace
          }
          if s.payload_uuid.respond_to?(:puid_hex) && (uuid_info = framework.db.payloads(payload_info).first)
            s.payload_uuid.registered = true
            s.payload_uuid.name = uuid_info['name']
            s.payload_uuid.timestamp = uuid_info['timestamp']
          else
            s.payload_uuid.registered = false
          end
        end
      end

      # If the session is valid, register it with the framework and
      # notify any waiters we may have.
      if (s)
        register_session(s)
      end

      return s
    end
    puts("not if (self.session)")
    nil
  end

  #
  # Registers a session with the framework and notifies any waiters of the
  # new session.
  #
  def register_session(session)
    # Register the session with the framework
    framework.sessions.register(session)

    # Call the handler's on_session() method
    if session.respond_to?(:bootstrap)
      session.bootstrap(datastore, self)
    else
      # Process the auto-run scripts for this session
      if session.respond_to?(:process_autoruns)
        session.process_autoruns(datastore)
      end
      on_session(session)
    end

    # If there is an exploit associated with this payload, then let's notify
    # anyone who is interested that this exploit succeeded
    if assoc_exploit
      framework.events.on_exploit_success(assoc_exploit, session)
    end

    # Notify waiters that they should be ready to rock
    session_waiter_event.notify(session)

    # Decrement the pending connections counter now that we've processed
    # one session.
    self.pending_connections -= 1

    # Count the number of sessions we have registered
    self.sessions += 1
  end

  attr_accessor :session_waiter_event # :nodoc:
  attr_accessor :pending_connections  # :nodoc:
  attr_accessor :sessions # :nodoc:

end

end

# The default none handler
require 'msf/core/handler/none'

