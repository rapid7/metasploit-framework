# -*- coding: binary -*-

require 'rex/post/meterpreter/extensions/sniffer/tlv'
require 'rex/post/meterpreter/extensions/sniffer/command_ids'
require 'rex/post/meterpreter/extension'

module Rex
module Post
module Meterpreter
module Extensions
module Sniffer

###
#
# This meterpreter extension can be used to capture remote traffic
#
###
class Sniffer < Extension

  def self.extension_id
    EXTENSION_ID_SNIFFER
  end

  def initialize(client)
    super(client, 'sniffer')

    client.register_extension_aliases(
      [
        {
          'name' => 'sniffer',
          'ext'  => self
        },
      ])
  end


  # Enumerate the remote sniffable interfaces
  def interfaces()
    ifaces = []
    request = Packet.create_request(COMMAND_ID_SNIFFER_INTERFACES)
    response = client.send_request(request)
    response.each(TLV_TYPE_SNIFFER_INTERFACES) { |p|
      vals  = p.tlvs.map{|x| x.value }
      iface = { }
      if vals.length == 8
        # Windows
        ikeys = %W{idx name description type mtu wireless usable dhcp}
      else
        # Mettle
        ikeys = %W{idx name description usable}
      end
      ikeys.each_index { |i| iface[ikeys[i]] = vals[i] }
      ifaces << iface
    }
    return ifaces
  end

  # Start a packet capture on an opened interface
  def capture_start(intf,maxp=200000,filter="")
    request = Packet.create_request(COMMAND_ID_SNIFFER_CAPTURE_START)
    request.add_tlv(TLV_TYPE_SNIFFER_INTERFACE_ID, intf.to_i)
    request.add_tlv(TLV_TYPE_SNIFFER_PACKET_COUNT, maxp.to_i)
    request.add_tlv(TLV_TYPE_SNIFFER_ADDITIONAL_FILTER, filter) if filter.length > 0
    client.send_request(request)
  end

  # Stop an active packet capture
  def capture_stop(intf)
    request = Packet.create_request(COMMAND_ID_SNIFFER_CAPTURE_STOP)
    request.add_tlv(TLV_TYPE_SNIFFER_INTERFACE_ID, intf.to_i)
    response = client.send_request(request)
    {
      :packets => response.get_tlv_value(TLV_TYPE_SNIFFER_PACKET_COUNT),
      :bytes   => response.get_tlv_value(TLV_TYPE_SNIFFER_BYTE_COUNT),
    }
  end

  # Retrieve stats about a current capture
  def capture_stats(intf)
    request = Packet.create_request(COMMAND_ID_SNIFFER_CAPTURE_STATS)
    request.add_tlv(TLV_TYPE_SNIFFER_INTERFACE_ID, intf.to_i)
    response = client.send_request(request)
    {
      :packets => response.get_tlv_value(TLV_TYPE_SNIFFER_PACKET_COUNT),
      :bytes   => response.get_tlv_value(TLV_TYPE_SNIFFER_BYTE_COUNT),
    }
  end

  # Release packets from a current capture
  def capture_release(intf)
    request = Packet.create_request(COMMAND_ID_SNIFFER_CAPTURE_RELEASE)
    request.add_tlv(TLV_TYPE_SNIFFER_INTERFACE_ID, intf.to_i)
    response = client.send_request(request)
    {
      :packets => response.get_tlv_value(TLV_TYPE_SNIFFER_PACKET_COUNT),
      :bytes   => response.get_tlv_value(TLV_TYPE_SNIFFER_BYTE_COUNT),
    }
  end

  # Buffer the current capture to a readable buffer
  def capture_dump(intf)
    request = Packet.create_request(COMMAND_ID_SNIFFER_CAPTURE_DUMP)
    request.add_tlv(TLV_TYPE_SNIFFER_INTERFACE_ID, intf.to_i)
    response = client.send_request(request, 3600)
    {
      :packets => response.get_tlv_value(TLV_TYPE_SNIFFER_PACKET_COUNT),
      :bytes   => response.get_tlv_value(TLV_TYPE_SNIFFER_BYTE_COUNT),
      :linktype => response.get_tlv_value(TLV_TYPE_SNIFFER_INTERFACE_ID) || 1,
    }
  end

  # Retrieve the packet data for the specified capture
  def capture_dump_read(intf, len=16384)
    request = Packet.create_request(COMMAND_ID_SNIFFER_CAPTURE_DUMP_READ)
    request.add_tlv(TLV_TYPE_SNIFFER_INTERFACE_ID, intf.to_i)
    request.add_tlv(TLV_TYPE_SNIFFER_BYTE_COUNT, len.to_i)
    response = client.send_request(request, 3600)
    {
      :bytes   => response.get_tlv_value(TLV_TYPE_SNIFFER_BYTE_COUNT),
      :data    => response.get_tlv_value(TLV_TYPE_SNIFFER_PACKET)
    }
  end

end

end; end; end; end; end
