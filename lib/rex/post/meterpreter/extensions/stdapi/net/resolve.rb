#!/usr/bin/env ruby
# -*- coding: binary -*-

require 'rex/post/meterpreter/extensions/stdapi/tlv'

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
class Resolve

  ##
  #
  # Constructor
  #
  ##

  #
  # Initializes a Resolve instance that is used to resolve network addresses
  # on the remote machine.
  #
  def initialize(client)
    self.client = client
  end

  def resolve_host(hostname, family=AF_INET)
    request = Packet.create_request('stdapi_net_resolve_host')
    request.add_tlv(TLV_TYPE_HOST_NAME, hostname)
    request.add_tlv(TLV_TYPE_ADDR_TYPE, family)

    response = client.send_request(request)

    type = response.get_tlv_value(TLV_TYPE_ADDR_TYPE)
    raw = response.get_tlv_value(TLV_TYPE_IP)

    return raw_to_host_ip_pair(hostname, raw, type)
  end

  def resolve_hosts(hostnames, family=AF_INET)
    request = Packet.create_request('stdapi_net_resolve_hosts')
    request.add_tlv(TLV_TYPE_ADDR_TYPE, family)
    
    hostnames.each do |hostname|
      request.add_tlv(TLV_TYPE_HOST_NAME, hostname)
    end

    response = client.send_request(request)

    hosts = []
    raws = []
    types = []

    response.each(TLV_TYPE_IP) do |raw|
      raws << raw
    end

    response.each(TLV_TYPE_ADDR_TYPE) do |type|
      types << type
    end

    0.upto(hostnames.length - 1) do |i|
      raw = raws[i]
      type = types[i]
      host = hostnames[i]

      hosts << raw_to_host_ip_pair(host, raw.value, type.value)
    end

    return hosts
  end

  def raw_to_host_ip_pair(host, raw, type)
    if raw.nil? or host.nil?
      return nil
    end

    if raw.empty?
      ip = ""
    else
      if type == AF_INET
        ip = Rex::Socket.addr_ntoa(raw[0..3])
      else
        ip = Rex::Socket.addr_ntoa(raw[0..16])
      end
    end

    result = { :hostname => host, :ip => ip }

    return result
  end

protected

  attr_accessor :client # :nodoc:

end

end; end; end; end; end; end
