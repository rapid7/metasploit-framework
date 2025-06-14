# -*- coding: binary -*-
module Msf
module Handler

module Generic

  include Msf::Handler

  #
  # Returns the handler type of none since payloads that use this handler
  # have no connection.
  #
  def self.handler_type
    'none'
  end

  #
  # Returns none to indicate no connection.
  #
  def self.general_handler_type
    'none'
  end

  # This is necessary for find-sock style payloads.
  #
  def handler(*args)
    create_session(*args)

    Claimed
  end

  #
  # Always wait at least 5 seconds for this payload (due to channel delays)
  #
  def wfs_delay
    datastore['WfsDelay'] > 4 ? datastore['WfsDelay'] : 5
  end
end

end
end

