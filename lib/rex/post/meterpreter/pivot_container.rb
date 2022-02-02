# -*- coding: binary -*-

module Rex
module Post
module Meterpreter

###
#
# This interface is meant to be included by things that are meant to contain
# zero or more pivot instances in the form of a hash.
#
###
module PivotContainer

  #
  # Initializes the pivot association hash
  #
  def initialize_pivots
    self.pivot_sessions = {}
    self.pivot_listeners = {}
  end

  #
  # Adds a pivot to the container that is indexed by the pivoted
  # session guid.
  #
  def add_pivot_session(pivot)
    self.pivot_sessions[pivot.pivoted_session.session_guid] = pivot
  end

  def add_pivot_listener(listener)
    self.pivot_listeners[listener.id] = listener
  end

  #
  # Looks up a pivot instance based on its pivoted session guid.
  #
  def find_pivot_session(pivot_session_guid)
    return self.pivot_sessions[pivot_session_guid]
  end

  def find_pivot_listener(listener_id)
    return self.pivot_listeners[listener_id]
  end

  #
  # Removes a pivot based on its pivoted session guid.
  #
  def remove_pivot_session(pivot_session_guid)
    return self.pivot_sessions.delete(pivot_session_guid)
  end

  def remove_pivot_listener(listener_id)
    return self.pivot_listeners.delete(listener_id)
  end

  #
  # The hash of pivot sessions.
  #
  attr_reader :pivot_sessions

  attr_reader :pivot_listeners

protected

  attr_writer :pivot_sessions # :nodoc:

  attr_writer :pivot_listeners # :nodoc:

end

end; end; end
