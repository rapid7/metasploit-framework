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
# This class represents a logical physical interface
# on the remote machine.
#
###
class Interface

  ##
  #
  # Constructor
  #
  ##

  #
  # Returns a logical interface and initializes it to the supplied
  # parameters.
  #
  def initialize(opts={})
    self.index    = opts[:index] || -1
    self.mac_addr = opts[:mac_addr]
    self.mac_name = opts[:mac_name]
    self.mtu      = opts[:mtu]
    self.flags    = opts[:flags]
    self.addrs    = opts[:addrs]
    self.netmasks = opts[:netmasks]
    self.scopes   = opts[:scopes]
  end

  #
  # Returns a pretty string representation of the interface's properties.
  #
  def pretty
    macocts = []
    mac_addr.each_byte { |o| macocts << o }
    macocts += [0] * (6 - macocts.size) if macocts.size < 6

    info = [
      ["Name"         , mac_name  ],
      ["Hardware MAC" , sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
        macocts[0], macocts[1], macocts[2],
        macocts[3], macocts[4], macocts[5])],
      ["MTU"          , mtu       ],
      ["Flags"        , flags     ],
    ]

    # If all went as planned, addrs and netmasks will have the same number
    # of elements and be properly ordered such that they match up
    # correctly.
    addr_masks = addrs.zip(netmasks)

    addr_masks.select { |a| Rex::Socket.is_ipv4?(a[0]) }.each { |a|
      info << [ "IPv4 Address", a[0] ]
      info << [ "IPv4 Netmask", a[1] ]
    }
    addr_masks.select { |a| Rex::Socket.is_ipv6?(a[0]) }.each { |a|
      info << [ "IPv6 Address", a[0] ]
      info << [ "IPv6 Netmask", a[1] ]
    }

    pad = info.map{|i| i[0] }.max_by{|k|k.length}.length

    ret = sprintf(
        "Interface %2d\n" +
        "============\n",
        index
      )

    info.map {|k,v|
      next if v.nil?
      ret << k.ljust(pad) + " : #{v}\n"
    }

    ret
  end

  #
  # The first address associated with this Interface
  #
  def ip
    addrs.first
  end

  #
  # The index of the interface.
  #
  attr_accessor :index
  #
  # An Array of IP addresses bound to the Interface.
  #
  attr_accessor :addrs
  #
  # The physical (MAC) address of the NIC.
  #
  attr_accessor :mac_addr
  #
  # The name of the interface.
  #
  attr_accessor :mac_name
  #
  # The MTU associated with the interface.
  #
  attr_accessor :mtu
  #
  # The flags associated with the interface.
  #
  attr_accessor :flags
  #
  # An Array of netmasks. This will have the same number of elements as #addrs
  #
  attr_accessor :netmasks
  #
  # An Array of IPv6 address scopes. This will have the same number of elements as #addrs
  #
  attr_accessor :scopes
end

end; end; end; end; end; end
