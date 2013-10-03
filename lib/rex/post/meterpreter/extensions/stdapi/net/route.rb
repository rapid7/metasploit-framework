#!/usr/bin/env ruby
# -*- coding: binary -*-

require 'ipaddr'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Net

###
#
# Represents a logical network route.
#
###
class Route

  ##
  #
  # Constructor
  #
  ##

  #
  # Initializes a route instance.
  #
  def initialize(subnet, netmask, gateway, interface='', metric=0)
    self.subnet  = IPAddr.new_ntoh(subnet).to_s
    self.netmask = IPAddr.new_ntoh(netmask).to_s
    self.gateway = IPAddr.new_ntoh(gateway).to_s
    self.interface = interface
    self.metric = metric
  end

  #
  # Provides a pretty version of the route.
  #
  def pretty
    return sprintf("%16s %16s %16s %d %16s", subnet, netmask, gateway, metric, interface)
  end

  #
  # The subnet mask associated with the route.
  #
  attr_accessor :subnet
  #
  # The netmask of the subnet route.
  #
  attr_accessor :netmask
  #
  # The gateway to take for the subnet route.
  #
  attr_accessor :gateway
  #
  # The interface to take for the subnet route.
  #
  attr_accessor :interface
  #
  # The metric of the route.
  #
  attr_accessor :metric


end

end; end; end; end; end; end
