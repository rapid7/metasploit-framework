# -*- coding: binary -*-
require 'msf/core'
require 'msf/core/handler/reverse_tcp'

module Msf
module Handler

###
#
# This module implements the reverse TCP handler that works with
# "allports" stagers. This handler listens on a single TCP port,
# and the operating system redirects all incoming connections
# on all ports to this listening port. This requires iptables
# or another packet filter to be used in order to work properly
#
###
module ReverseTcpAllPorts

  include Msf::Handler::ReverseTcp

  #
  # Returns the string representation of the handler type, in this case
  # 'reverse_tcp_allports'.
  #
  def self.handler_type
    return "reverse_tcp_allports"
  end

  #
  # Returns the connection-described general handler type, in this case
  # 'reverse'.
  #
  def self.general_handler_type
    "reverse"
  end

  #
  # Override the default port to be '1'
  #
  def initialize(info = {})
    super

    register_options(
      [
        OptPort.new('LPORT', [true, 'The starting port number to connect back on', 1])
      ], Msf::Handler::ReverseTcpAllPorts)
  end
end
end
end
