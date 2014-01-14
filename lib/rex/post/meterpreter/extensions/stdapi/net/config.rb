# -*- coding: binary -*-

require 'rex/post/meterpreter/extensions/stdapi/tlv'
require 'rex/post/meterpreter/extensions/stdapi/net/arp'
require 'rex/post/meterpreter/extensions/stdapi/net/route'
require 'rex/post/meterpreter/extensions/stdapi/net/netstat'
require 'rex/post/meterpreter/extensions/stdapi/net/interface'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Net

###
#
# This class provides an interface to the network configuration
# that exists on the remote machine, such as interfaces, and
# routes.
#
###
class Config

  ##
  #
  # Constructor
  #
  ##

  #
  # Initializes a Config instance that is used to get information about the
  # network configuration of the remote machine.
  #
  def initialize(client)
    self.client = client
  end

  ##
  #
  # Interfaces
  #
  ##

  #
  # Enumerates each interface.
  #
  def each_interface(&block)
    get_interfaces().each(&block)
  end

  #
  # Returns an array of network interfaces with each element.
  #
  # being an Interface
  def get_interfaces
    request = Packet.create_request('stdapi_net_config_get_interfaces')
    ifaces  = []

    response = client.send_request(request)

    response.each(TLV_TYPE_NETWORK_INTERFACE) { |iface|
      addrs = []
      netmasks = []
      scopes = []
      while (a = iface.get_tlv_value(TLV_TYPE_IP, addrs.length))
        # Netmasks aren't tightly associated with addresses, they're
        # just thrown all together in the interface TLV ordered to
        # match up. This could be done better by creating another
        # GroupTlv type for addresses containing an address, a netmask,
        # and possibly a scope.
        n = iface.get_tlv_value(TLV_TYPE_NETMASK, addrs.length)
        if (n.nil?)
          # Some systems can't report a netmask, only a network
          # prefix, so figure out the netmask from that.
          n = iface.get_tlv_value(TLV_TYPE_IP_PREFIX, addrs.length)
          if n
            n = Rex::Socket.bit2netmask(n, !!(a.length == 16))
          end
        else
          n = Rex::Socket.addr_ntoa(n)
        end
        s = iface.get_tlv_value(TLV_TYPE_IP6_SCOPE, addrs.length)
        scopes[addrs.length] = s if s
        netmasks[addrs.length] = n if n
        addrs << Rex::Socket.addr_ntoa(a)
      end
      ifaces << Interface.new(
          :index    => iface.get_tlv_value(TLV_TYPE_INTERFACE_INDEX),
          :mac_addr => iface.get_tlv_value(TLV_TYPE_MAC_ADDRESS),
          :mac_name => iface.get_tlv_value(TLV_TYPE_MAC_NAME),
          :mtu      => iface.get_tlv_value(TLV_TYPE_INTERFACE_MTU),
          :flags    => iface.get_tlv_value(TLV_TYPE_INTERFACE_FLAGS),
          :addrs    => addrs,
          :netmasks => netmasks,
          :scopes   => scopes
        )
    }

    return ifaces
  end

  alias interfaces get_interfaces

  ##
  #
  # Network connections
  #
  ##

  #
  # Returns an array of network connection entries with each element being a Netstat.
  #

  def get_netstat
    request = Packet.create_request('stdapi_net_config_get_netstat')
                netstat  = []

    response = client.send_request(request)

    # Build out the array of netstat
    response.each(TLV_TYPE_NETSTAT_ENTRY) { |connection|
      netstat << Netstat.new(
                      :local_addr   => connection.get_tlv_value(TLV_TYPE_LOCAL_HOST_RAW),
          :remote_addr  => connection.get_tlv_value(TLV_TYPE_PEER_HOST_RAW),
          :local_port   => connection.get_tlv_value(TLV_TYPE_LOCAL_PORT),
          :remote_port  => connection.get_tlv_value(TLV_TYPE_PEER_PORT),
          :protocol     => connection.get_tlv_value(TLV_TYPE_MAC_NAME), # tcp/tcp6/udp/udp6
          :state        => connection.get_tlv_value(TLV_TYPE_SUBNET_STRING),
          :uid          => connection.get_tlv_value(TLV_TYPE_PID),
          :inode        => connection.get_tlv_value(TLV_TYPE_ROUTE_METRIC),
          :pid_name     => connection.get_tlv_value(TLV_TYPE_PROCESS_NAME)
          )
    }

    return netstat
  end

  alias netstat get_netstat

  ##
  #
  # Routing
  #
  ##

  #
  # Returns an array of arp entries with each element being an Arp.
  #

  def get_arp_table
    request = Packet.create_request('stdapi_net_config_get_arp_table')
                arps  = []

    response = client.send_request(request)

    # Build out the array of arp
    response.each(TLV_TYPE_ARP_ENTRY) { |arp|
      arps << Arp.new(
          :ip_addr   => arp.get_tlv_value(TLV_TYPE_IP),
          :mac_addr  => arp.get_tlv_value(TLV_TYPE_MAC_ADDRESS),
          :interface => arp.get_tlv_value(TLV_TYPE_MAC_NAME)
          )
    }

    return arps
  end

  alias arp_table get_arp_table

  #
  # Enumerates each route.
  #
  def each_route(&block)
    get_routes().each(&block)
  end

  #
  # Returns an array of routes with each element being a Route.
  #
  def get_routes
    request = Packet.create_request('stdapi_net_config_get_routes')
    routes  = []

    response = client.send_request(request)

    # Build out the array of routes
    # Note: This will include both IPv4 and IPv6 routes
    response.each(TLV_TYPE_NETWORK_ROUTE) { |route|
      routes << Route.new(
          route.get_tlv_value(TLV_TYPE_SUBNET),
          route.get_tlv_value(TLV_TYPE_NETMASK),
          route.get_tlv_value(TLV_TYPE_GATEWAY),
          route.get_tlv_value(TLV_TYPE_STRING),
          route.get_tlv_value(TLV_TYPE_ROUTE_METRIC))
    }

    return routes
  end

  alias routes get_routes

  #
  # Adds a route to the target machine.
  #
  def add_route(subnet, netmask, gateway)
    request = Packet.create_request('stdapi_net_config_add_route')

    request.add_tlv(TLV_TYPE_SUBNET_STRING, subnet)
    request.add_tlv(TLV_TYPE_NETMASK_STRING, netmask)
    request.add_tlv(TLV_TYPE_GATEWAY_STRING, gateway)

    response = client.send_request(request)

    return true
  end

  #
  # Removes a route from the target machine.
  #
  def remove_route(subnet, netmask, gateway)
    request = Packet.create_request('stdapi_net_config_remove_route')

    request.add_tlv(TLV_TYPE_SUBNET_STRING, subnet)
    request.add_tlv(TLV_TYPE_NETMASK_STRING, netmask)
    request.add_tlv(TLV_TYPE_GATEWAY_STRING, gateway)

    response = client.send_request(request)

    return true
  end

  #
  # Get's the current proxy configuration
  #
  def get_proxy_config()
    request = Packet.create_request('stdapi_net_config_get_proxy')

    response = client.send_request(request)

    proxy_config = {
      :autodetect    => response.get_tlv_value(TLV_TYPE_PROXY_CFG_AUTODETECT),
      :autoconfigurl => response.get_tlv_value(TLV_TYPE_PROXY_CFG_AUTOCONFIGURL),
      :proxy         => response.get_tlv_value(TLV_TYPE_PROXY_CFG_PROXY),
      :proxybypass   => response.get_tlv_value(TLV_TYPE_PROXY_CFG_PROXYBYPASS)
    }

    return proxy_config
  end

protected

  attr_accessor :client # :nodoc:

end

end; end; end; end; end; end
