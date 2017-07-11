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
    self.pivots = {}
    self.pivot_listeners = {}
  end

  #
  # Adds a pivot to the container that is indexed by the pivoted
  # session guid.
  #
  def add_pivot(pivot)
    self.pivots[pivot.pivot_session_guid] = pivot
  end

  def add_pivot_listener(listener)
    self.pivot_listeners[listener.id] = listener
  end

  #
  # Looks up a pivot instance based on its pivoted session guid.
  #
  def find_pivot(pivot_session_guid)
    return self.pivots[pivot_session_guid]
  end

  def find_pivot_listener(listener_id)
    return self.pivot_listeners[listener_id]
  end

  #
  # Removes a pivot based on its pivoted session guid.
  #
  def remove_pivot(pivot_session_guid)
    return self.pivots.delete(pivot_session_guid)
  end

  #
  # The hash of pivots.
  #
  attr_reader :pivots

  attr_reader :pivot_listeners

protected

  attr_writer :pivots # :nodoc:

  attr_writer :pivot_listeners # :nodoc:

end

end; end; end
