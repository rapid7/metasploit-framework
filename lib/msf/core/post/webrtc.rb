# -*- coding: binary -*-

module Msf::Post::WebRTC

  #
  # Connects to a video chat session as an answerer
  #
  # @param offerer_id [String] The offerer's ID in order to join the video chat
  # @return void
  #
  def connect_video_chat(server, channel, offerer_id)
    interface = load_interface('answerer.html')
    interface.gsub!(/\=SERVER\=/, server)
    interface.gsub!(/\=RHOST\=/, rhost)
    interface.gsub!(/\=CHANNEL\=/, channel)
    interface.gsub!(/\=OFFERERID\=/, offerer_id)

    tmp_interface = Tempfile.new(['answerer', '.html'])
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
    interface_code.gsub!(/\=WEBRTCAPIJS\=/, load_api_code)
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
