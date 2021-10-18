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

  def handler(sock)
    create_session(sock)
    Claimed
  end

end

end
end

