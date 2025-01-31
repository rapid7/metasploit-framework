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
# This class provides DNS resolution from the perspective
# of the remote host.
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

  def resolve_host(hostname, family = AF_INET)
    request = Packet.create_request(COMMAND_ID_STDAPI_NET_RESOLVE_HOST)
    request.add_tlv(TLV_TYPE_HOST_NAME, hostname)
    request.add_tlv(TLV_TYPE_ADDR_TYPE, family)

    response = client.send_request(request)

    ips = []
    if response.has_tlv?(TLV_TYPE_RESOLVE_HOST_ENTRY)
      response.each(TLV_TYPE_RESOLVE_HOST_ENTRY) do |tlv|
        tlv.each(TLV_TYPE_IP) do |ip|
          ips << raw_to_host_ip_pair(hostname, ip.value)[:ip]
        end
      end
    elsif response.has_tlv?(TLV_TYPE_IP)
      ip = response.get_tlv_value(TLV_TYPE_IP)
      ips << raw_to_host_ip_pair(hostname, ip)[:ip]
    end

    { hostname: hostname, ip: ips.first, ips: ips }
  end

  def resolve_hosts(hostnames, family = AF_INET)
    result = []
    request = Packet.create_request(COMMAND_ID_STDAPI_NET_RESOLVE_HOSTS)
    request.add_tlv(TLV_TYPE_ADDR_TYPE, family)

    hostnames.each do |hostname|
      request.add_tlv(TLV_TYPE_HOST_NAME, hostname)
    end

    response = client.send_request(request)

    if response.has_tlv?(TLV_TYPE_RESOLVE_HOST_ENTRY)
      response.each_with_index(TLV_TYPE_RESOLVE_HOST_ENTRY) do |tlv, index|
        ips = []
        tlv.each(TLV_TYPE_IP) do |ip|
          ips << raw_to_host_ip_pair(hostnames[index], ip.value)[:ip]
        end
        result << { hostname: hostnames[index], ip: ips.first, ips: ips }
      end
    elsif response.has_tlv?(TLV_TYPE_IP)
      response.each_with_index(TLV_TYPE_IP) do |tlv, index|
        ips = [raw_to_host_ip_pair(hostnames[index], tlv.value)[:ip]]
        result << { hostname: hostnames[index], ip: ips.first, ips: ips }
      end
    end

    result
  end

  def raw_to_host_ip_pair(host, raw)
    if raw.nil? or host.nil?
      return nil
    end

    ip = nil
    if raw.length == 4 || raw.length == 16
      ip = Rex::Socket.addr_ntoa(raw)
    elsif raw.length != 0
      wlog("hostname resolution failed, the returned address is corrupt (hostname: #{host}, length: #{raw.length})")
    end

    result = { :hostname => host, :ip => ip }

    return result
  end

protected

  attr_accessor :client # :nodoc:

end

end; end; end; end; end; end
