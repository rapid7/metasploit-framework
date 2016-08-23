# -*- coding: binary -*-

require 'rex/post/meterpreter/channel'
require 'rex/post/meterpreter/channels/pools/audio'

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
              include Msf::Post::Common

              def initialize(client)
                @client = client
              end

              def session
                @client
              end

              def mic_list
                response = client.send_request(Packet.create_request('stdapi_sys_audio_get_interfaces'))
                names = []
                response.get_tlvs(TLV_TYPE_AUDIO_INTERFACE_NAME).each do |tlv|
                  names << tlv.value
                end
                names
              end

              # Starts streaming from audio source of index
              def mic_start
                request = Packet.create_request('channel_create_stdapi_net_mic_broadcast')

                response = client.send_request(request)
                channel_id = response.get_tlv_value(TLV_TYPE_CHANNEL_ID)

                if(channel_id)
                  # audio_channel = Rex::Post::Meterpreter::Channels::Pools::StreamPool.new(
                  #     client,
                  #     channel_id,
                  #     "stdapi_net_mic_broadcast",
                  #     CHANNEL_FLAG_SYNCHRONOUS
                  # )
                  audio_channel =  Rex::Post::Meterpreter::Channels::Pools::Audio.open(self.client)
                end

                return response, audio_channel
              end

              # def mic_stop
              #   client.send_request(Packet.create_request('mic_stop'))
              #   true
              # end

              attr_accessor :client
            end
          end
        end
      end
    end
  end
end
