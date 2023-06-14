require 'rex'

lib = File.join(Msf::Config.install_root, "test", "lib")
$LOAD_PATH.push(lib) unless $LOAD_PATH.include?(lib)
require 'module_test'

class MetasploitModule < Msf::Post

  include Msf::ModuleTest::PostTest

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Test Meterpreter ExtAPI Stuff',
        'Description' => %q{ This module will test Windows Extended API methods },
        'License' => MSF_LICENSE,
        'Author' => [ 'Ben Campbell'],
        'Platform' => [ 'windows', ],
        'SessionTypes' => [ 'meterpreter' ]
      )
    )
  end

  #
  # Check the extension is loaded...
  #
  def setup
    unless session.extapi
      vprint_status("Loading extapi extension...")
      begin
        session.core.use("extapi")
      rescue Errno::ENOENT, Rex::Post::Meterpreter::ExtensionLoadError
        print_status("This module is only available in a windows meterpreter session.")
        return
      end
    end

    super
  end

  def test_clipboard_management
    return skip('session platform is not windows') unless session.platform == 'windows'

    vprint_status("Starting clipboard management tests")

    it "should return an array of clipboard data" do
      return skip('session does not support COMMAND_ID_EXTAPI_CLIPBOARD_GET_DATA') unless session.commands.include?(Rex::Post::Meterpreter::Extensions::Extapi::COMMAND_ID_EXTAPI_CLIPBOARD_GET_DATA)

      ret = false
      clipboard = session.extapi.clipboard.get_data(false)

      if clipboard && clipboard.any? && clipboard.first[:type]
        vprint_status("Clipboard: #{clipboard}")
        ret = true
      end

      ret
    end

    it "should return clipboard jpg dimensions" do
      return skip("Session doesn't implement railgun.user32, skipping jpg test") unless session.commands.include?(Rex::Post::Meterpreter::Extensions::Stdapi::COMMAND_ID_STDAPI_RAILGUN_API) && session.railgun.user32

      # VK_PRINTSCREEN 154 Maybe needed on XP?
      # VK_SNAPSHOT 44
      session.railgun.user32.keybd_event(44, 0, 0, 0)
      session.railgun.user32.keybd_event(44, 0, 'KEYEVENTF_KEYUP', 0)

      clipboard = session.extapi.clipboard.get_data(false)
      ret = clipboard && clipboard.first && (clipboard.first[:type] == :jpg) && clipboard.first[:width]
      ret
    end

    it "should set clipboard text" do
      return skip('session does not support COMMAND_ID_EXTAPI_CLIPBOARD_SET_DATA') unless session.commands.include?(Rex::Post::Meterpreter::Extensions::Extapi::COMMAND_ID_EXTAPI_CLIPBOARD_SET_DATA)

      text = Rex::Text.rand_text_alphanumeric(1024)
      ret = session.extapi.clipboard.set_text(text)

      if ret
        clipboard = session.extapi.clipboard.get_data(false)
        ret = clipboard && clipboard.first && (clipboard.first[:type] == :text) && (clipboard.first[:data] == text)
      end

      ret
    end

    it "should download clipboard text data" do
      return skip('session does not support COMMAND_ID_EXTAPI_CLIPBOARD_SET_DATA') unless session.commands.include?(Rex::Post::Meterpreter::Extensions::Extapi::COMMAND_ID_EXTAPI_CLIPBOARD_SET_DATA)

      text = Rex::Text.rand_text_alphanumeric(1024)
      ret = session.extapi.clipboard.set_text(text)
      clipboard = session.extapi.clipboard.get_data(true)
      ret = clipboard && clipboard.first && (clipboard.first[:type] == :text) && (clipboard.first[:data] == text)
      ret
    end

    it "should download clipboard jpg data" do
      return skip("Session doesn't implement railgun.user32, skipping download_jpg test") unless session.commands.include?(Rex::Post::Meterpreter::Extensions::Stdapi::COMMAND_ID_STDAPI_RAILGUN_API) && session.railgun.user32

      ret = false

      # VK_PRINTSCREEN 154 Maybe needed on XP?
      # VK_SNAPSHOT 44
      session.railgun.user32.keybd_event(44, 0, 0, 0)
      session.railgun.user32.keybd_event(44, 0, 'KEYEVENTF_KEYUP', 0)

      clipboard = session.extapi.clipboard.get_data(true)
      if clipboard && clipboard.first && (clipboard.first[:type] == :jpg) && !(clipboard.first[:data].empty?)
        # JPG Magic Bytes
        ret = (clipboard.first[:data][0, 2] == "\xFF\xD8")
      end

      ret
    end
  end

  def test_service_management
    return skip('session platform is not windows') unless session.platform == 'windows'

    vprint_status("Starting service management tests")
    services = nil

    it "should return an array of services" do
      return skip('session does not support COMMAND_ID_EXTAPI_SERVICE_ENUM') unless session.commands.include?(Rex::Post::Meterpreter::Extensions::Extapi::COMMAND_ID_EXTAPI_SERVICE_ENUM)

      services = session.extapi.service.enumerate

      if services && services.any? && services.first[:name]
        vprint_status("First service: #{services.first}")
        ret = true
      end

      ret
    end

    it "should return service information" do
      return skip('session does not support COMMAND_ID_EXTAPI_SERVICE_QUERY') unless session.commands.include?(Rex::Post::Meterpreter::Extensions::Extapi::COMMAND_ID_EXTAPI_SERVICE_QUERY)

      service = session.extapi.service.query(services.first[:name])
      vprint_status("Service info: #{service}")
      if service && service[:starttype]
        ret = true
      end

      ret
    end
  end

  def test_desktop_windows_management
    return skip('session platform is not windows') unless session.platform == 'windows'

    vprint_status("Starting desktop windows management tests")
    windows = nil

    it "should return an array of windows" do
      return skip('session does not support COMMAND_ID_EXTAPI_WINDOW_ENUM') unless session.commands.include?(Rex::Post::Meterpreter::Extensions::Extapi::COMMAND_ID_EXTAPI_WINDOW_ENUM)

      windows = session.extapi.window.enumerate(false, nil)

      if windows && windows.any? && windows.first[:handle]
        vprint_status("First window: #{windows.first}")
        ret = true
      end

      ret
    end

    it "should return an array including unknown windows" do
      return skip('session does not support COMMAND_ID_EXTAPI_WINDOW_ENUM') unless session.commands.include?(Rex::Post::Meterpreter::Extensions::Extapi::COMMAND_ID_EXTAPI_WINDOW_ENUM)

      ret = false
      windows = session.extapi.window.enumerate(true, nil)

      if windows && windows.any?
        unknowns = windows.select { |w| w[:title] == "<unknown>" }
        ret = !unknowns.empty?
      end

      ret
    end

    it "should return an array of a windows children" do
      return skip('session does not support COMMAND_ID_EXTAPI_WINDOW_ENUM') unless session.commands.include?(Rex::Post::Meterpreter::Extensions::Extapi::COMMAND_ID_EXTAPI_WINDOW_ENUM)

      windows = session.extapi.window.enumerate(true, nil)
      parent = windows.select { |w| w[:title] =~ /program manager/i }
      return skip("Unable to find a suitable parent, skipping test") unless parent && parent.first

      ret = false
      children = session.extapi.window.enumerate(true, parent.first[:handle])
      if children && children.any?
        vprint_status("First child: #{children.first}")
        ret = true
      end
      ret
    end
  end
end
