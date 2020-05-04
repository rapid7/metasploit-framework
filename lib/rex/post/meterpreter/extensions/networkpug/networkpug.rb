# -*- coding: binary -*-

require 'rex/post/meterpreter/extensions/networkpug/tlv'

module Rex
module Post
module Meterpreter
module Extensions
module NetworkPug

# NetworkPug implements a remote packet recieve/send on a network interface
# on the remote machine

class NetworkPug < Extension

  def self.extension_id
    EXTENSION_ID_NETWORKPUG
  end

  def initialize(client)
    super(client, 'networkpug')

    client.register_extension_aliases(
      [
        {
          'name' => 'networkpug',
          'ext'  => self
        },
      ])
  end

  def networkpug_start(interface, filter)
    request = Packet.create_request(COMMAND_ID_NETWORKPUG_START)
    request.add_tlv(TLV_TYPE_NETWORKPUG_INTERFACE, interface)
    request.add_tlv(TLV_TYPE_NETWORKPUG_FILTER, filter) if(filter and filter != "")
    response = client.send_request(request)

    channel = nil
    channel_id = response.get_tlv_value(TLV_TYPE_CHANNEL_ID)

    if(channel_id)
      channel = Rex::Post::Meterpreter::Channels::Pools::StreamPool.new(
        client,
        channel_id,
        'networkpug_interface',
        CHANNEL_FLAG_SYNCHRONOUS,
        response
      )
    end

    return response, channel
  end

  def networkpug_stop(interface)
    request = Packet.create_request(COMMAND_ID_NETWORKPUG_STOP)
    request.add_tlv(TLV_TYPE_NETWORKPUG_INTERFACE, interface)
    client.send_request(request)
  end

end

end; end; end; end; end
