# -*- coding: binary -*-
module Msf
module Handler

###
#
# The 'none' handler, for no connection.
#
###
module None
  include Msf::Handler

  #
  # Returns the handler type of none since payloads that use this handler
  # have no connection.
  #
  def self.handler_type
    return "none"
  end

  #
  # Returns none to indicate no connection.
  #
  def self.general_handler_type
    return "none"
  end

end

end
end
