# -*- coding: binary -*-
require 'msf/core/handler/find_port'

module Msf
module Handler

###
#
# This handler expects a interactive TTY on the supplied socket/io object
#
###
module FindTty

  include FindPort

  #
  # Returns the string representation of the handler type, in this case
  # 'none', which is kind of a lie, but we don't have a better way to
  # handle this yet
  #
  def self.handler_type
    return "none"
  end

  #
  # Returns the connection oriented general handler type, in this case
  # 'none'
  #
  def self.general_handler_type
    "none"
  end

  #
  # Remove the CPORT option from our included FindPort class
  #
  def initialize(info = {})
    super
    options.remove_option('CPORT')
  end

protected

  def _check_shell(sock)
    # Verify that the modem is online
    if(sock.respond_to?('commandstate'))
      return (sock.commandstate ? false : true)
    end
    return true
  end

end

end
end
