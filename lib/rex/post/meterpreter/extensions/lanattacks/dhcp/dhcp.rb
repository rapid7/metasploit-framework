#!/usr/bin/env ruby
# -*- coding: binary -*-

require 'rex/post/meterpreter/extensions/lanattacks/tlv'

module Rex
module Post
module Meterpreter
module Extensions
module Lanattacks
module Dhcp

###
#
# DHCP Server functionality
#
###
class Dhcp

  def initialize(client)
    @client = client
  end

  def start
    client.send_request(Packet.create_request('lanattacks_start_dhcp'))
    true
  end

  def reset
    client.send_request(Packet.create_request('lanattacks_reset_dhcp'))
    true
  end

  def set_option(name, value)
    request = Packet.create_request('lanattacks_set_dhcp_option')
    request.add_tlv(TLV_TYPE_LANATTACKS_OPTION_NAME, name)
    request.add_tlv(TLV_TYPE_LANATTACKS_OPTION, value)
    client.send_request(request)
    true
  end

  def load_options(datastore)
    # TODO: change this so that all of the options are set in a single
    # payload rather than firing off lots of calls separately
    datastore.each do |name, value|
      if Regexp.new('DHCPIPSTART|DHCPIPEND|NETMASK|ROUTER|DNSSERVER|BROADCAST|'+
          'SERVEONCE|PXE|HOSTNAME|HOSTSTART|FILENAME|PXECONF|SRVHOST') =~ name
        set_option(name, value)
      end
    end
  end

  def stop
    client.send_request(Packet.create_request('lanattacks_stop_dhcp'))
    true
  end

  def log
    response = client.send_request(Packet.create_request('lanattacks_dhcp_log'))
    entries = []
    if( response.result == 0 )
      log = response.get_tlv_value( TLV_TYPE_LANATTACKS_RAW )
      while log.length > 0
        mac = log.slice!(0..5)
        ip = log.slice!(0..3)
        entries << {
         :mac => mac,
         :ip  => ip
        }
      end
    end
    entries
  end

  attr_accessor :client

end

end; end; end; end; end; end
