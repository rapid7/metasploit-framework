
require 'msf/core'
require 'rex'

$:.push "test/lib" unless $:.include? "test/lib"
require 'module_test'

class Metasploit4 < Msf::Post

  include Msf::ModuleTest::PostTest

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Testing Meterpreter ExtAPI Stuff',
        'Description'   => %q{ This module will test Windows Extended API methods },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Ben Campbell'],
        'Platform'      => [ 'windows', ],
        'SessionTypes'  => [ 'meterpreter' ]
      ))

  end

  #
  # Check the extension is loaded...
  #
  def setup

    unless client.extapi
      vprint_status("Loading extapi extension...")
      begin
        client.core.use("extapi")
      rescue Errno::ENOENT
        print_error("This module is only available in a windows meterpreter session.")
        return
      end
    end

    super
  end

  def test_clipboard_management
    vprint_status("Starting clipboard management tests")
    services = nil

    if client.commands.include? "extapi_clipboard_get_data"
      ret = false
      it "should return an array of clipboard data" do
        clipboard = client.extapi.clipboard.get_data(false)

        if clipboard && clipboard.any? && clipboard.first[:type]
          vprint_status("Clipboard: #{clipboard}")
          ret = true
        end

        ret
      end

      if client.railgun.user32
        it "should return clipboard jpg dimensions" do
          ret = false

          #VK_PRINTSCREEN 154 Maybe needed on XP?
          #VK_SNAPSHOT 44
          client.railgun.user32.keybd_event(44,0,0,0)
          client.railgun.user32.keybd_event(44, 0, 'KEYEVENTF_KEYUP', 0)

          clipboard = client.extapi.clipboard.get_data(false)
          ret = clipboard && clipboard.first && (clipboard.first[:type] == :jpg) && clipboard.first[:width]
        end
      else
        print_status("Session doesn't implement railgun.user32, skipping jpg test")
      end

      if client.commands.include? "extapi_clipboard_set_data"
        ret = false

        it "should set clipboard text" do
          ret = false
          text = Rex::Text.rand_text_alphanumeric(1024)
          ret = client.extapi.clipboard.set_text(text)

          if ret
            clipboard = client.extapi.clipboard.get_data(false)
            ret = clipboard && clipboard.first && (clipboard.first[:type] == :text) && (clipboard.first[:data] == text)
          end

          ret
        end
      else
        vprint_status("Session doesn't implement extapi_clipboard_set_data, skipping test")
      end

      it "should download clipboard text data" do
        ret = false
        text = Rex::Text.rand_text_alphanumeric(1024)
        ret = client.extapi.clipboard.set_text(text)
        clipboard = client.extapi.clipboard.get_data(true)
        ret =  clipboard && clipboard.first && (clipboard.first[:type] == :text) && (clipboard.first[:data] == text)
      end

      if client.railgun.user32
        it "should download clipboard jpg data" do
          ret = false

          #VK_PRINTSCREEN 154 Maybe needed on XP?
          #VK_SNAPSHOT 44
          client.railgun.user32.keybd_event(44,0,0,0)
          client.railgun.user32.keybd_event(44, 0, 'KEYEVENTF_KEYUP', 0)

          clipboard = client.extapi.clipboard.get_data(true)
          if clipboard && clipboard.first && (clipboard.first[:type] == :jpg) && !(clipboard.first[:data].empty?)
            # JPG Magic Bytes
            ret = (clipboard.first[:data][0,2] == "\xFF\xD8")
          end

          ret
        end
      else
        print_status("Session doesn't implement railgun.user32, skipping download_jpg test")
      end
    else
      print_status("Session doesn't implement extapi_clipboard_get_data, skipping test")
    end
  end

  def test_service_management
    vprint_status("Starting service management tests")
    services = nil

    if client.commands.include? "extapi_service_enum"
      ret = false
      it "should return an array of services" do
        services = client.extapi.service.enumerate

        if services && services.any? && services.first[:name]
          vprint_status("First service: #{services.first}")
          ret = true
        end

        ret
      end

      if client.commands.include? "extapi_service_query"
        ret = false

        it "should return service information" do
          service = client.extapi.service.query(services.first[:name])
          vprint_status("Service info: #{service}")
          if service && service[:starttype]
            ret = true
          end

          ret
        end
      else
        print_status("Session doesn't implement extapi_service_query, skipping test")
      end
    else
      print_status("Session doesn't implement extapi_service_enum, skipping test")
    end
  end

  def test_desktop_windows_management
    vprint_status("Starting desktop windows management tests")
    windows = nil

    if client.commands.include? "extapi_window_enum"
      ret = false
      it "should return an array of windows" do
        windows = client.extapi.window.enumerate(false, nil)

        if windows && windows.any? && windows.first[:handle]
          vprint_status("First window: #{windows.first}")
          ret = true
        end

        ret
      end

      it "should return an array including unknown windows" do
        ret = false
        windows = client.extapi.window.enumerate(true, nil)

        if windows && windows.any?
          unknowns = windows.select {|w| w[:title] == "<unknown>"}
          ret = !unknowns.empty?
        end

        ret
      end

      parent = windows.select {|w| w[:title] =~ /program manager/i}

      if parent && parent.first
        it "should return an array of a windows children" do
          ret = false
          children = client.extapi.window.enumerate(true, parent.first[:handle])
          if children && children.any?
            vprint_status("First child: #{children.first}")
            ret = true
          end

          ret
        end
      else
        print_status("Unable to find a suitable parent, skipping test")
      end
    else
      print_status("Session doesn't implement extapi_window_enum, skipping test")
    end
  end
end
