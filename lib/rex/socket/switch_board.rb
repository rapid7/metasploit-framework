# -*- coding: binary -*-
require 'singleton'
require 'thread'
require 'rex/socket'

module Rex
module Socket

###
#
# This class provides a global routing table that associates subnets with Comm
# classes.  Comm classes are used to instantiate objects that are tied to
# remote network entities.  For example, the Local Comm class is used to
# building network connections directly from the local machine whereas, for
# instance, a Meterpreter Comm would build a local socket pair that is
# associated with a connection established by a remote entity.  This can be
# seen as a uniform way of communicating with hosts through arbitrary
# channels.
#
###
class SwitchBoard

  include Singleton
  include Enumerable

  def initialize
    @_initialized = false
  end

  ###
  #
  # This class represents a logical switch board route.
  # TODO: Enable this to work with IPv6 addresses
  #
  ###
  class Route
    def initialize(subnet, netmask, comm)
      self.subnet      = subnet
      self.netmask     = netmask
      self.comm        = comm
      self.subnet_nbo  = Socket.resolv_nbo_i(subnet)
      self.netmask_nbo = Socket.resolv_nbo_i(netmask)
    end

    #
    # Sort according to bitmask
    #
    def <=>(other)
      self.bitmask <=> other.bitmask
    end

    #
    # Convert the netmask to a bitmask and cache it.
    #
    def bitmask
      @_bitmask = Socket.net2bitmask(self.netmask) if (@_bitmask == nil)
      @_bitmask
    end

    attr_reader :subnet, :netmask, :comm
    attr_reader :subnet_nbo, :netmask_nbo
  protected
    attr_writer :subnet, :netmask, :comm
    attr_writer :subnet_nbo, :netmask_nbo
  end

  ##
  #
  # Class method wrappers
  #
  ##

  #
  # Adds a route to the switch board routing table using the supplied Comm
  # instance.
  #
  def self.add_route(subnet, mask, comm)
    ret = self.instance.add_route(subnet, mask, comm)
    if ret && comm.respond_to?(:routes) && comm.routes.kind_of?(Array)
      comm.routes << "#{subnet}/#{mask}"
    end
    ret
  end

  #
  # Removes a route from the switch board routing table for the supplied
  # subnet routing through the supplied Comm instance.
  #
  def self.remove_route(subnet, mask, comm)
    ret = self.instance.remove_route(subnet, mask, comm)
    if ret && comm.respond_to?(:routes) && comm.routes.kind_of?(Array)
      comm.routes.delete "#{subnet}/#{mask}"
    end
    ret
  end

  #
  # Flush all the routes from the switch board routing table.
  #
  def self.flush_routes
    ret = self.instance.flush_routes
  end

  #
  # Enumerate each route in the routing table.
  #
  def self.each(&block)
    self.instance.each(&block)
  end

  #
  # Returns the array of routes.
  #
  def self.routes
    self.instance.routes
  end

  def self.route_exists?(subnet, mask)
    self.instance.route_exists?(subnet, mask)
  end

  #
  # Returns the Comm instance that should be used for the supplied address.
  # If no comm can be found, the default Local Comm is returned.
  #
  def self.best_comm(addr)
    self.instance.best_comm(addr)
  end

  #
  # Removes all routes that go through the supplied Comm.
  #
  def self.remove_by_comm(comm)
    self.instance.remove_by_comm(comm)
  end

  ##
  #
  # Instance methods
  #
  ##

  #
  # Adds a route for a given subnet and netmask destined through a given comm
  # instance.
  #
  def add_route(subnet, mask, comm)
    # If a bitmask was supplied, convert it.
    netmask = (mask.to_s =~ /^\d+$/) ? Rex::Socket.bit2netmask(mask.to_i) : mask
    rv      = true

    _init

    mutex.synchronize {
      # If the route already exists, return false to the caller.
      if (route_exists?(subnet, netmask) == false)
        self.routes << Route.new(subnet, netmask, comm)
      else
        rv = false
      end
    }

    rv
  end

  #
  # Removes a route for a given subnet and netmask destined through a given
  # comm instance.
  #
  def remove_route(subnet, mask, comm)
    # If a bitmask was supplied, convert it.
    netmask = (mask.to_s =~ /^\d+$/) ? Rex::Socket.bit2netmask(mask.to_i) : mask
    rv      = false

    _init

    mutex.synchronize {
      self.routes.delete_if { |route|
        if (route.subnet == subnet and route.netmask == netmask and route.comm == comm)
          rv = true
        else
          false
        end
      }
    }

    rv
  end

  #
  # Flushes all established routes.
  #
  def flush_routes
    _init

    # Remove each of the individual routes so the comms don't think they're
    # still routing after a flush.
    self.routes.each { |r|
      if r.comm.respond_to? :routes
        r.comm.routes.delete("#{r.subnet}/#{r.netmask}")
      end
    }
    # Re-initialize to an empty array
    self.routes = Array.new
  end

  #
  # Checks to see if a route already exists for the supplied subnet and
  # netmask.
  #
  def route_exists?(subnet, netmask)
    each { |route|
      return true if (route.subnet == subnet and route.netmask == netmask)
    }

    false
  end

  #
  # Enumerates each entry in the routing table.
  #
  def each(&block)
    _init

    routes.each(&block)
  end

  #
  # Finds the best possible comm for the supplied target address.
  #
  def best_comm(addr)

    addr_nbo = Socket.resolv_nbo_i(addr)
    comm     = nil
    msb      = 0

    each { |route|
      if ((route.subnet_nbo & route.netmask_nbo) ==
          (addr_nbo & route.netmask_nbo))
        if (route.bitmask >= msb)
          comm = route.comm
          msb  = route.bitmask
        end
      end
    }

    comm
  end

  #
  # Remove all routes that go through the supplied comm.
  #
  def remove_by_comm(comm)
    _init
    mutex.synchronize {
      routes.delete_if { |route|
        route.comm == comm
      }
    }
  end

  #
  # The routes array.
  #
  attr_reader :routes
  #
  # The mutex protecting the routes array.
  #
  attr_reader :mutex

protected

  attr_writer :routes, :mutex # :nodoc:

  #
  # Initializes the underlying stuff.
  #
  def _init
    if (@_initialized != true)
      @_initialized = true
      self.routes   = Array.new
      self.mutex    = Mutex.new
    end
  end

end

end
end
