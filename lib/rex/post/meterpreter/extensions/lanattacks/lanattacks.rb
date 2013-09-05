#!/usr/bin/env ruby
# -*- coding: binary -*-

require 'rex/post/meterpreter/extensions/lanattacks/tlv'

module Rex
module Post
module Meterpreter
module Extensions
module Lanattacks

###
#
# This meterpreter extension can currently run DHCP and TFTP servers
#
###
class Lanattacks < Extension

  def initialize(client)
    super(client, 'lanattacks')

    client.register_extension_aliases(
      [{
          'name' => 'lanattacks',
          'ext'  => self
       },])
  end

  def start_dhcp
    client.send_request(Packet.create_request('lanattacks_start_dhcp'))
    true
  end

  def reset_dhcp
    client.send_request(Packet.create_request('lanattacks_reset_dhcp'))
    true
  end

  def set_dhcp_option(name, value)
    request = Packet.create_request('lanattacks_set_dhcp_option')
    request.add_tlv(TLV_TYPE_LANATTACKS_OPTION_NAME, name)
    request.add_tlv(TLV_TYPE_LANATTACKS_OPTION, value)
    client.send_request(request)
    true
  end

  def load_dhcp_options(datastore)
    datastore.each do |name, value|
      if Regexp.new('DHCPIPSTART|DHCPIPEND|NETMASK|ROUTER|DNSSERVER|BROADCAST|'+
          'SERVEONCE|PXE|HOSTNAME|HOSTSTART|FILENAME|PXECONF|SRVHOST') =~ name
        set_dhcp_option(name,value)
      end
    end
  end

  def stop_dhcp
    client.send_request(Packet.create_request('lanattacks_stop_dhcp'))
    true
  end

  def dhcp_log
    response = client.send_request(Packet.create_request('lanattacks_dhcp_log'))
    entries = []
    if( response.result == 0 )
      log = response.get_tlv_value( TLV_TYPE_LANATTACKS_RAW )
      while log.length > 0
        mac = log.slice!(0..5)
        ip = log.slice!(0..3)
        entries << [ mac, ip ]
      end
    end
    entries
  end

  def start_tftp
    client.send_request(Packet.create_request('lanattacks_start_tftp'))
    true
  end

  def reset_tftp
    client.send_request(Packet.create_request('lanattacks_reset_tftp'))
    true
  end

  def add_tftp_file(filename, data)
    request = Packet.create_request('lanattacks_add_tftp_file')
    request.add_tlv(TLV_TYPE_LANATTACKS_OPTION_NAME, filename)
    request.add_tlv(TLV_TYPE_LANATTACKS_RAW, data, false, true) #compress it
    client.send_request(request)
    true
  end

  def stop_tftp
    client.send_request(Packet.create_request('lanattacks_stop_tftp'))
    true
  end
end

end; end; end; end; end
