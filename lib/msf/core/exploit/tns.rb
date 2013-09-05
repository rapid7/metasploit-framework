# -*- coding: binary -*-
require 'msf/core'

module Msf

###
#
# This module exposes methods for querying a remote TNS service
#
###
module Exploit::Remote::TNS

  include Exploit::Remote::Tcp

  #
  # Creates an instance of a TNS exploit module.
  #
  def initialize(info = {})
    super

    # Register the options that all TNS exploits may make use of.
    register_options(
      [
        Opt::RHOST,
        Opt::RPORT(1521),
      ], Msf::Exploit::Remote::TNS)
  end

  def tns_packet(connect_data)

    packet_length = [58 + connect_data.length].pack('n')

    # Packet length
    pkt =  packet_length
    # Checksum
    pkt << "\x00\x00"
    # Packet Type: Connect(1)
    pkt << "\x01"
    # Reserved
    pkt << "\x00"
    # Header Checksum
    pkt << "\x00\x00"
    # Version
    pkt << "\x01\x36"
    # Version (Compatible)
    pkt << "\x01\x2C"
    pkt << "\x00\x00\x08\x00"
    pkt << "\x7F\xFF"
    pkt << "\x7F\x08"
    pkt << "\x00\x00"
    pkt << "\x00\x01"
    pkt << [connect_data.length].pack('n')
    pkt << "\x00\x3A"
    pkt << "\x00\x00\x00\x00"
    pkt << "\x00\x00\x00\x00"
    pkt << "\x00"
    pkt << "\x00"
    pkt << "\x00\x00\x00\x00"
    # Unique Connection ID
    pkt << "\x00\x00\x34\xE6\x00\x00\x00\x01"
    # Connect Data
    pkt << "\x00\x00\x00\x00\x00\x00\x00\x00"
    pkt << connect_data

    return pkt

  end

  def tns_packet10g(connect_data)

    packet_length = [58 + connect_data.length].pack('n')

    # Packet length
    pkt =  packet_length
    # Checksum
    pkt << "\x00\x00"
    # Packet Type: Connect(1)
    pkt << "\x01"
    # Reserved
    pkt << "\x00"
    # Header Checksum
    pkt << "\x00\x00"
    # Version
    pkt << "\x01\x39"
    # Version (Compatible)
    pkt << "\x01\x2C"
    pkt << "\x00\x81\x08\x00"
    pkt << "\x7F\xFF"
    pkt << "\x7F\x08"
    pkt << "\x00\x00"
    pkt << "\x00\x01"
    pkt << [connect_data.length].pack('n')
    pkt << "\x00\x3A"
    pkt << "\x00\x00\x07\xf8"
    pkt << "\x0c\x0c\x00\x00"
    pkt << "\x00" * 22
    pkt << connect_data

    return pkt

  end

end
end
