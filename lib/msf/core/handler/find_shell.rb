# -*- coding: binary -*-
require 'msf/core/handler/find_port'

module Msf
module Handler

###
#
# This handler expects a plain Unix command shell on the supplied socket
#
###
module FindShell

  include FindPort

  #
  # Returns the string representation of the handler type, in this case
  # 'find_shell'.
  #
  def self.handler_type
    return "find_shell"
  end

  #
  # Returns the connection oriented general handler type, in this case
  # 'find'.
  #
  def self.general_handler_type
    "find"
  end

  #
  # Remove the CPORT option from our included FindPort class
  #
  def initialize(info = {})
    super
    options.remove_option('CPORT')
  end

protected



end

end
end
